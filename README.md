# Certificate Transparency Service for oidc-vpn-manager

This service is designed to be exposed to users and administrators of the managed OpenVPN service as an unauthenticated readable record.

Users and administrators should be able to read the service records via an API or Web UI to see all the issued certificates for the OpenVPN service in a manner that an individual user or device can be searched for. Administrators, who have authenticated via OIDC, can further interrogate the records to see under what conditions a certificate was issued (e.g. what User Agent was presented for the requesting device, what OS was used to request the certificate) in a way that trends can be identified and potential vulnerabilities can be identified.

This service is typically accessed via the [frontend service](https://github.com/oidc-vpn-manager/frontend_service), but can also be exposed separately for automated queries.

## Contributing

Contributions are welcome! Since this is Free Software:

- No copyright assignment needed, but will be gratefully received.
- **Feature requests and improvements are gratefully received**, however they may not be implemented due to time constraints or if they don't align with the developer's vision for the project

---

## License

This software is released under the [GNU Affero General Public License version 3](LICENSE).

## AI Assistance Disclosure

This code was developed with assistance from AI tools. While released under a permissive license that allows unrestricted reuse, we acknowledge that portions of the implementation may have been influenced by AI training data. Should any copyright assertions or claims arise regarding uncredited imported code, the affected portions will be rewritten to remove or properly credit any unlicensed or uncredited work.
