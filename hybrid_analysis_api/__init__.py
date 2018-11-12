import sys

from requests import session

if sys.version_info.major < 3:
    from urlparse import urljoin
else:
    from urllib.parse import urljoin


class HybridAnalysis(object):
    """
    Hybrid Analysis REST API wrapper

    """
    __api_root = 'https://www.hybrid-analysis.com/api/v2/'
    environments = {
        100: 'Windows 7 32 bit',
        110: 'Windows 7 32 bit (HWP Support)',
        120: 'Windows 7 64 bit',
        200: 'Android Static Analysis',
        300: 'Linux (Ubuntu 16.04, 64 bit)',
    }

    def __init__(self, api_key, user_agent='Falcon Sandbox'):
        self.session = session()
        self.session.headers = {
            'api-key': api_key,
            'user-agent': user_agent
        }

    def __connect(self, method, url_path, **kwargs):
        response = self.session.request(method, urljoin(self.__api_root, url_path), **kwargs)
        response.raise_for_status()

        if response.headers['Content-Type'] == 'application/json':
            return response.json()
        return response.content

    def search_hash(self, file_hash):
        """
        Summary for a given hash

        :param file_hash: MD5, SHA1 or SHA256
        :return:
        """
        return self.__connect('POST', 'search/hash', data={'hash': file_hash})

    def search_hashes(self, file_hashes):
        """
        Summary for given hashes

        :param file_hashes: List of hashes. Allowed type: MD5, SHA1 or SHA256
        :return:
        """
        return self.__connect('POST', 'search/hashes', data={'hashes[]': file_hashes})

    def search_terms(self, terms):
        """
        Search the database using the search terms

        :param terms: dictionary containing the desired terms
        :return:
        """
        return self.__connect('POST', 'search/terms', data=terms)

    def quick_scan_state(self):
        """
        Return list of available scanners

        :return:
        """
        return self.__connect('GET', 'quick-scan/state')

    def quick_scan_file(self, scan_type, file_name, file_path, options=dict()):
        """
        Submit a file for quick scan, you can check results in overview endpoint

        :param scan_type: Type of scan, please see /quick-scan/state to see available scanners
        :param file_name: File name which will be reported
        :param file_path: File path where the file to be analyzed is stored
        :param options: Additional options
        :return:
        """
        options.update({'scan_type': scan_type})
        return self.__connect('POST', 'quick-scan/file', data=options,
                              files={'file': (file_name, open(file_path, 'rb'))})

    def quick_scan_url_to_file(self, scan_type, url, options=dict()):
        """
        Submit a file by URL for analysis

        :param scan_type: Type of scan, please see /quick-scan/state to see available scanners
        :param url: url of file to submit
        :param options: Additional options
        :return:
        """
        options.update({'scan_type': scan_type, 'url': url})
        return self.__connect('POST', 'quick-scan/url-to-file', data=options)

    def quick_scan_url_for_analysis(self, scan_type, url, options=dict()):
        """
        Submit an URL for analysis

        :param scan_type: type of scan, please see /quick-scan/state to see available scanners
        :param url: url for analyze
        :param options: Additional options
        :return:
        """
        options.update({'scan_type': scan_type, 'url': url})
        return self.__connect('POST', 'quick-scan/url-for-analysis', data=options)

    def quick_scan_id(self, scan_id):
        """
        Some scanners need time to process file, if in response `finished` is set to false, then you need use this
        endpoint to get final results

        :param scan_id: id of scan
        :return:
        """
        return self.__connect('GET', 'quick-scan/{}'.format(scan_id))

    def quick_scan_id_convert_to_full(self, environment_id, scan_id, options=dict()):
        """
        Convert quick scan to sandbox report

        :param environment_id: Environment ID
        :param scan_id: ID of quick scan to convert
        :param options: Additional options
        :return:
        """
        options.update({'environment_id': environment_id})
        return self.__connect('POST', 'quick-scan/{}/convert-to-full'.format(scan_id), data=options)

    def overview_sha256(self, sha256):
        """
        Return overview for hash

        :param sha256: SHA256 for lookup
        :return:
        """
        return self.__connect('GET', 'overview/{}'.format(sha256))

    def overview_sha256_refresh(self, sha256):
        """
        Refresh overview and download fresh data from external services

        :param sha256: SHA256 for lookup
        :return:
        """
        return self.__connect('GET', 'overview/{}/refresh'.format(sha256))

    def overview_sha256_summary(self, sha256):
        """
        Return overview for hash

        :param sha256: SHA256 for lookup
        :return:
        """
        return self.__connect('GET', 'overview/{}/summary'.format(sha256))

    def overview_sha256_sample(self, sha256):
        """
        Downloading sample file

        :param sha256: SHA256 for download
        :return:
        """
        return self.__connect('GET', 'overview/{}/sample'.format(sha256))

    def submit_file(self, environment_id, file_name, file_path, options=dict()):
        """
        Submit a file for analysis

        :param environment_id: Environment ID
        :param file_name: File name which will be reported
        :param file_path: File path where the file to be analyzed is stored
        :param options: Additional options
        :return:
        """
        options.update({'environment_id': environment_id})
        return self.__connect('POST', 'submit/file', data=options, files={'file': (file_name, open(file_path, 'rb'))})

    def submit_url_to_file(self, environment_id, url, options=dict()):
        """
        Submit a file by url for analysis

        :param environment_id: Environment ID
        :param url: url of file to submit
        :param options: Additional options
        :return:
        """
        options.update({'environment_id': environment_id, 'url': url})
        return self.__connect('POST', 'submit/url-to-file', data=options)

    def submit_url_for_analysis(self, environment_id, url, options=dict()):
        """
        Submit a url for analysis

        :param environment_id: Environment ID
        :param url: url for analyze
        :param options: Additional options
        :return:
        """
        options.update({'environment_id': environment_id, 'url': url})
        return self.__connect('POST', 'submit/url-for-analysis', data=options)

    def submit_hash_for_url(self, url):
        """
        Determine a SHA256 that an online file or URL submission will have when being processed by the system.
        Note: this is useful when looking up URL analysis

        :param url: Url to check
        :return:
        """
        return self.__connect('POST', 'submit/hash-for-url', data={'url': url})

    def submit_dropped_file(self, report_id, file_hash, options=dict()):
        """
        Submit dropped file for analysis

        :param report_id: Id of the report from which the file should be analyzed.
                          Id in one of format: \'jobId\' or \'sha256:environmentId\'
        :param file_hash: SHA256 of dropped file for analyze
        :param options: Additional options
        :return:
        """
        options.update({'id': report_id, 'file_hash': file_hash})
        return self.__connect('POST', 'submit/dropped-file', data=options)

    def report_id_state(self, report_id):
        """
        Return state of a submission

        :param report_id: Id in one of format: \'jobId\' or \'sha256:environmentId\'
        :return:
        """
        return self.__connect('GET', 'report/{}/state'.format(report_id))

    def report_id_summary(self, report_id):
        """
        Return summary of a submission

        :param report_id: Id in one of format: \'jobId\' or \'sha256:environmentId\'
        :return:
        """
        return self.__connect('GET', 'report/{}/summary'.format(report_id))

    def report_summary(self, report_ids):
        """
        Return summary of multiple submissions

        :param report_ids: List of ids.  Allowed format: jobId, md5:environmentId, sha1:environmentId or
        sha256:environmentId
        :return:
        """
        return self.__connect('POST', 'report/summary', data={'hashes[]': report_ids})

    def report_id_file_type(self, report_id, file_type):
        """
        Downloading report data (e.g. JSON, XML, PCAP)

        :param report_id: Id in one of format: \'jobId\' or \'sha256:environmentId\'
        :param file_type: Type of requested content, available types:
            - xml - The XML report as application/xml content and *.gz compressed.
            - json - The JSON report as application/json content
            - html - The HTML report as text/html content and *.gz compressed
            - pdf - The PDF report as application/pdf content
            - maec - The MAEC (4.1) report as application/xml content
            - stix - The STIX report as application/xml content
            - misp - The MISP XML report as application/xml content
            - misp-json - The MISP JSON report as application/json content
            - openioc - The OpenIOC (1.1) report as application/xml content
            - bin - The binary sample as application/octet-stream and *.gz compressed. Note: if the file was uploaded
            with \'no_share_vt\' (i.e. not shared), this might fail.
            - crt - The binary sample certificate file (is available) as application/octet-stream content
            - memory - The process memory dump files as application/octet-stream and zip compressed.
            - pcap - The PCAP network traffic capture file as application/octet-stream and *.gz compressed.
        :return:
        """
        return self.__connect('GET', 'report/{}/file/{}'.format(report_id, file_type))

    def report_id_screenshots(self, report_id):
        """
        Retrieve an array of screenshots from a report in the Base64 format

        :param report_id: Id in one of format: \'jobId\' or \'sha256:environmentId\'
        :return:
        """
        return self.__connect('GET', 'report/{}/screenshots'.format(report_id))

    def report_id_dropped_file_raw_hash(self, report_id, hash_file):
        """
        Retrieve single extracted/dropped binaries files for a report

        :param report_id: Id in one of format: \'jobId\' or \'sha256:environmentId\'
        :param hash_file: SHA256 of dropped file
        :return:
        """
        return self.__connect('GET', 'report/{}/dropped-file-raw/{}'.format(report_id, hash_file))

    def report_id_dropped_files(self, report_id):
        """
        Retrieve all extracted/dropped binaries files for a report, as zip

        :param report_id: Id in one of format: \'jobId\' or \'sha256:environmentId\'
        :return:
        """
        return self.__connect('GET', 'report/{}/dropped-files'.format(report_id))

    def system_version(self):
        """
        Return system elements versions

        :return:
        """
        return self.__connect('GET', 'system/version')

    def system_environments(self):
        """
        Return information about available execution environments

        :return:
        """
        return self.__connect('GET', 'system/environments')

    def system_stats(self):
        """
        Contains a variety of webservice statistics, e.g. the total number of submissions, unique submissions,
        signature ID distribution, user comments, etc.

        :return:
        """
        return self.__connect('GET', 'system/stats')

    def system_state(self):
        """
        A full system state query, including all available action scripts, environments, files in progress, etc.

        :return:
        """
        return self.__connect('GET', 'system/state')

    def system_configuration(self):
        """
        A partial information about instance configuration

        :return:
        """
        return self.__connect('GET', 'system/configuration')

    def system_backend(self):
        """
        Return information about configured backend nodes

        :return:
        """
        return self.__connect('GET', 'system/backend')

    def system_queue_size(self):
        """
        Return information about queue size

        :return:
        """
        return self.__connect('GET', 'system/queue-size')

    def system_in_progress(self):
        """
        Return information about processed samples

        :return:
        """
        return self.__connect('GET', 'system/in-progress')

    def system_total_submissions(self):
        """
        Return total number of submission

        :return:
        """
        return self.__connect('GET', 'system/total-submissions')

    def system_heartbeat(self):
        """
        Return heartbeat

        :return:
        """
        return self.__connect('GET', 'system/heartbeat')

    def key_current(self):
        """
        Return information about the used API key and it limits

        :return:
        """
        return self.__connect('GET', 'key/current')

    def feed_latest(self):
        """
        Access a JSON feed (summary information) of last 250 reports from 24h

        :return:
        """
        return self.__connect('GET', 'feed/latest')
