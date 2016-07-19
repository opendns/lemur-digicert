"""This plugin manages communications with Digicert.

.. module: lemur.plugins.lemur_digicert.digicert
    :platform: Unix
    :synopsis: This module is responsible for communicating with the DigiCert '
    Advanced API.
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Chris Dorros <cdorros[at]cisco[dot]com>
"""
import arrow
import requests

from flask import current_app

from lemur.plugins.bases import IssuerPlugin, SourcePlugin
import lemur_digicert as digicert
from lemur_digicert import constants

import json
import time

# DigiCert CertCentral (v2 API) Documentation
# https://www.digicert.com/services/v2/documentation


def process_options(options, csr):
    """Set the incoming issuer options to DigiCert fields/options.

    :param options:
    :param csr:
    :return: dict or valid DigiCert options
    """
    current_app.logger.info("csr: {0}".format(csr))
    current_app.logger.info("options: {0}".format(options))

    data = {
        "certificate":
            {
                "common_name": options['commonName'],
                "csr": csr,
                "signature_hash":
                    current_app.config.get("DIGICERT_SIGNATURE_HASH"),
            },
        "organization":
            {
                "id": current_app.config.get("DIGICERT_ORG_ID")
            },
    }

    # add Private CA Cert ID for Private SSL Request
    if current_app.config.get("DIGICERT_REQUEST_TYPE") == 'PRIVATE_SSL_PLUS':
        if current_app.config.get("DIGICERT_SIGNATURE_HASH") is None:
            raise Exception("Must provide DIGICERT_SIGNATURE_HASH for "
                            "DIGICERT_REQUEST_TYPE 'PRIVATE_SSL_PLUS'")
        else:
            data['certificate']['ca_cert_id'] = \
                current_app.config.get("DIGICERT_CA_CERT_ID")

    # add SANs if present
    if options.get('extensions', 'subAltNames'):
        dns_names = []
        for san in options['extensions']['subAltNames']['names']:
            dns_names.append(str(san['value']))

        data['certificate']['dns_names'] = dns_names

    if options.get('validityEnd'):
        end_date, period = get_default_issuance(options)
        data['validity_years'] = period

    return data


def get_default_issuance(options):
    """Get the default time range for certificates.

    :param options:
    :return:
    """
    end_date = arrow.get(options['validityEnd'])
    specific_end_date = end_date.replace(days=-1).format("MM/DD/YYYY")

    now = arrow.utcnow()
    then = arrow.get(options['validityEnd'])

    if then < now.replace(years=+1):
        validity_period = '1'
    elif then < now.replace(years=+2):
        validity_period = '2'
    elif then < now.replace(years=+3):
        validity_period = '3'
    else:
        raise Exception("DigiCert issued certificates cannot exceed three"
                        " years in validity")

    return specific_end_date, validity_period


class DigiCertIssuerPlugin(IssuerPlugin):
    """Wrap the Digicert Issuer API."""

    title = 'DigiCert'
    slug = 'digicert-issuer'
    description = "Enables the creation of certificates by"
    "the DigiCert REST API."
    version = digicert.VERSION

    author = 'Chris Dorros'
    author_url = 'github.com/opendns/lemur-digicert'

    def __init__(self, *args, **kwargs):
        """Initialize the issuer with the appropriate details."""
        self.session = requests.Session()
        super(DigiCertIssuerPlugin, self).__init__(*args, **kwargs)

    def get_certificates(self, certificate_id):
        """Get certificate in PEM format
        server, intermediate, root
        """
        url = "{0}/certificate/{1}/download/format/pem_all".format(
            current_app.config.get("DIGICERT_URL"), str(certificate_id))
        headers = {
            'X-DC-DEVKEY': current_app.config.get('DIGICERT_API_KEY'),
        }
        response = self.session.get(url, headers=headers)

        delimeter = '-----END CERTIFICATE-----\r\n'
        certs = [
            line + delimeter
            for line
            in response.text.split(delimeter)
            if line != ""]

        server_cert = certs[0]
        int_cert = certs[1]
        root_cert = certs[2]

        return server_cert, int_cert, root_cert

    def request_certificate(self, issuer_options, csr):
        """Submits a certificate request"""

        # Build the proper API-URL for digicert
        request_type = current_app.config.get("DIGICERT_REQUEST_TYPE")
        digicert_url = current_app.config.get("DIGICERT_URL")
        sub_alt_name = issuer_options.get('extensions', 'subAltName')
        url = self.build_request_url(request_type, sub_alt_name, digicert_url)

        data = process_options(issuer_options, csr)
        headers = {
            'X-DC-DEVKEY': current_app.config.get('DIGICERT_API_KEY'),
            'Content-Type': 'application/json',
        }

        response = self.session.post(url, 
                                     data=json.dumps(data),
                                     headers=headers)
        current_app.logger.info("response.text: {0}".format(response.text))
        current_app.logger.info("response.json: {0}".format(response.json))

        request_id = response.json()['requests'][0]['id']
        return request_id

    def approve_request(self, request_id):
        """Approves certificate request"""
        url = "{0}/request/{1}/status".format(
            current_app.config.get("DIGICERT_URL"), str(request_id))

        data = {
            "status": "approved",
            "processor_comment": "auto-approved by Lemur"
        }
        headers = {
            'X-DC-DEVKEY': current_app.config.get('DIGICERT_API_KEY'),
            'Content-Type': 'application/json',
        }

        response = self.session.put(
            url, data=json.dumps(data), headers=headers)

        return response

    def get_order_info(self, order_id):
        """Get certificate order information"""
        url = "{0}/order/certificate/{1}".format(
            current_app.config.get("DIGICERT_URL"), str(order_id))

        headers = {
            'X-DC-DEVKEY': current_app.config.get('DIGICERT_API_KEY'),
        }
        response = self.session.get(url, headers=headers)
        return response.json()

    def get_request_info(self, request_id):
        """Get certificate request information"""
        url = "{0}/request/{1}".format(
            current_app.config.get("DIGICERT_URL"), str(request_id))
        headers = {
            'X-DC-DEVKEY': current_app.config.get('DIGICERT_API_KEY'),
            'Content-Type': 'application/json',
        }
        response = self.session.get(url, headers=headers)
        return response.json()

    def create_certificate(self, csr, issuer_options):
        """Create a DigiCert certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        # submit certificate request
        current_app.logger.info(
            "Requesting a new digicert certificate: {0}".format(issuer_options))
        request_id = self.request_certificate(issuer_options, csr)

        # approve the request
        current_app.logger.info(
            "Auto-approving digicert certificate: {0}".format(issuer_options))
        current_app.logger.info("request ID: {0}".format(request_id))
        response = self.approve_request(request_id)
        current_app.logger.info("put response: {0}".format(response))

        # get orderID from request
        current_app.logger.info("Fetching order ID")
        request_info = self.get_request_info(request_id)
        order_id = request_info['order']['id']
        current_app.logger.info("orderid: {0}".format(order_id))

        # wait until the cert is ready to download (capped)
        current_app.logger.info("Waiting for cert to become available...")

        order_info = self.get_order_info(order_id)
        waited = 0
        while (order_info['status'] != 'issued') and (waited < 600):
            time.sleep(10)
            waited += 10
            current_app.logger.info("waiting for cert issuance; sleeping 10s")
            order_info = self.get_order_info(order_id)

        # get certID from order
        current_app.logger.info("Fetching cert ID")
        certificate_id = order_info['certificate']['id']
        current_app.logger.info("certid: {0}".format(certificate_id))

        # download cert in PEM format
        current_app.logger.info("Downloading certs")
        server_cert, int_cert, root_cert = self.get_certificates(certificate_id)

        return server_cert, int_cert

    @staticmethod
    def create_authority(options):
        """Create an authority.

        Creates an authority, this authority is then used by Lemur to
        allow a user to specify which Certificate Authority they want
        to sign their certificate.

        :param options:
        :return:
        """
        role = {'username': '', 'password': '', 'name': 'digicert'}
        return constants.DIGICERT_ROOT, "", [role]

    @staticmethod
    def build_request_url(request_type, sub_alt_names, digicert_url):
        """Build the order request url.

        Create the correct URL for the Digicert API call for Requests.
        This is a string formatting method and is used only to build the
        certificate request end point URL for the API depending on the
        certificate that was was requested from the caller.

        :param request_type:
        :param sub_alt_names:
        :param digicert_url:
        :return: string representation of DigiCert API endpoint for order.
        """

        # Decide which API endpoint to use based on Private vs Public cert
        # Private SSL Certs
        if 'PRIVATE_SSL_PLUS' in request_type:
            private_cert = True
        elif 'SSL_PLUS' in request_type:
            private_cert = False
        else:
            raise Exception("Invalid DIGICERT_REQUEST_TYPE: {0}".format(
                request_type))

        # Decide if we need to add 'multi_domain' to the uri for SAN certs
        # certs.
        if sub_alt_names:
            if 'subAltNames' in sub_alt_names.keys():
                names = sub_alt_names['subAltNames']['names']
                current_app.logger.debug('Number of SubAltNames: %d' % len(
                    names))
                if len(names) > 0:
                    current_app.logger.info('Cert Type: Multi-Domain SSL (SAN)')
                    san_cert = True
                else:
                    current_app.logger.info('Cert Type: Simple SSL')
                    san_cert = False
            else:
                san_cert = False
        else:
            san_cert = False

        # Build the order URL from the decisions made above
        if san_cert:
            order_url = "ssl_multi_domain"
        else:
            order_url = "ssl_plus"

        # Prefix "private" to the cert
        if private_cert:
            order_url = "private_{0}".format(order_url)

        # Finally tack on the full URI path
        order_url = "/order/certificate/{0}".format(order_url)

        # Put together the full URL and return
        url = "{0}{1}".format(digicert_url, order_url)
        current_app.logger.info("Final Request URL: {0}".format(url))
        return url
