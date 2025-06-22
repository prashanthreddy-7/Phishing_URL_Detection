import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url

        self.domain = ""
        self.whois_response = None
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception as e:
            print(f"Error fetching URL content: {e}")
            self.soup = None

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception as e:
            print(f"Error parsing URL: {e}")
            self.domain = ""

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception as e:
            print(f"Error in WHOIS lookup: {e}")
            self.whois_response = None

        # List of features extraction methods
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Https())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # Method 1: UsingIp
    def UsingIp(self):
        try:
            ip = ipaddress.ip_address(self.domain)
            return -1  # URL uses an IP address
        except ValueError:
            return 1  # URL does not use an IP address

    # Method 2: longUrl
    def longUrl(self):
        return 1 if len(self.url) < 54 else -1  # Return -1 if URL length is greater than or equal to 54

    # Method 3: shortUrl
    def shortUrl(self):
        return 1 if len(self.url) > 20 else -1  # Return -1 if URL length is less than or equal to 20

    # Method 4: symbol
    def symbol(self):
        return -1 if re.search(r"[@_!#$%^&*()<>?/\\|}{~:]", self.url) else 1

    # Method 5: redirecting
    def redirecting(self):
        return -1 if self.url.count('//') > 1 else 1

    # Method 6: prefixSuffix
    def prefixSuffix(self):
        if '-' in self.domain:
            return -1
        return 1

    # Method 7: SubDomains
    def SubDomains(self):
        return -1 if len(self.domain.split('.')) > 2 else 1

    # Method 8: Https
    def Https(self):
        return -1 if self.urlparse.scheme != "https" else 1

    # Method 9: DomainRegLen
    def DomainRegLen(self):
        # Check if the whois_response and domain_name are valid
        if self.whois_response and hasattr(self.whois_response, 'domain_name') and self.whois_response.domain_name:
            # Handle case where domain_name is a list
            domain_name = self.whois_response.domain_name
            if isinstance(domain_name, list):
                domain_name = domain_name[0]  # Take the first domain name if it's a list
            return 1 if len(domain_name) > 10 else -1

        return 0  # Return a neutral value if no valid domain name is found

    # Method 10: Favicon
    def Favicon(self):
        if self.soup:
            favicon = self.soup.find('link', rel='icon')
            return -1 if favicon else 1
        return 1

    # Method 11: NonStdPort
    def NonStdPort(self):
        return -1 if self.urlparse.port not in [80, 443] else 1

    # Method 12: HTTPSDomainURL
    def HTTPSDomainURL(self):
        return -1 if self.domain not in self.url else 1

    # Method 13: RequestURL
    def RequestURL(self):
        return -1 if self.urlparse.path == '' else 1

    # Method 14: AnchorURL
    def AnchorURL(self):
        anchors = self.soup.find_all('a') if self.soup else []
        return -1 if len(anchors) > 5 else 1

    # Method 15: LinksInScriptTags
    def LinksInScriptTags(self):
        scripts = self.soup.find_all('script') if self.soup else []
        return -1 if len(scripts) > 2 else 1

    # Method 16: ServerFormHandler
    def ServerFormHandler(self):
        forms = self.soup.find_all('form') if self.soup else []
        return -1 if len(forms) == 0 else 1

    # Method 17: InfoEmail
    def InfoEmail(self):
        if self.whois_response and hasattr(self.whois_response, 'emails'):
            return -1 if self.whois_response.emails else 1
        return 1

    # Method 18: AbnormalURL
    def AbnormalURL(self):
        return -1 if re.search(r'(login|secure|account)', self.url) else 1

    # Method 19: WebsiteForwarding
    def WebsiteForwarding(self):
        return -1 if self.urlparse.hostname in ['tinyurl.com', 'bit.ly'] else 1

    # Method 20: StatusBarCust
    def StatusBarCust(self):
        return -1 if self.soup and 'status' in self.soup.text.lower() else 1

    # Method 21: DisableRightClick
    def DisableRightClick(self):
        return -1 if self.soup and 'contextmenu' in self.soup.text.lower() else 1

    # Method 22: UsingPopupWindow
    def UsingPopupWindow(self):
        return -1 if self.soup and 'window.open' in self.soup.text.lower() else 1

    # Method 23: IframeRedirection
    def IframeRedirection(self):
        if self.soup:
            return -1 if self.soup.find_all('iframe') else 1
        return 1

    # Method 24: AgeofDomain
    def AgeofDomain(self):
        if self.whois_response and hasattr(self.whois_response, 'creation_date') and self.whois_response.creation_date:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]  # Handle multiple creation dates
            return 1 if (datetime.now() - creation_date).days > 180 else -1
        return 1

    # Method 25: DNSRecording
    def DNSRecording(self):
        try:
            ip = socket.gethostbyname(self.domain)
            return 1 if ip else -1
        except socket.gaierror:
            return -1

    # Method 26: WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            traffic = requests.get(f"https://www.alexa.com/siteinfo/{self.domain}")
            return -1 if "Too many requests" in traffic.text else 1
        except:
            return -1

    # Method 27: PageRank
    def PageRank(self):
        return -1  # Placeholder for PageRank feature

    # Method 28: GoogleIndex
    def GoogleIndex(self):
        return -1  # Placeholder for Google Index feature

    # Method 29: LinksPointingToPage
    def LinksPointingToPage(self):
        return -1  # Placeholder for Links pointing to page feature

    # Method 30: StatsReport
    def StatsReport(self):
        return -1  # Placeholder for Stats Report feature

    # Method to get the list of features
    def getFeaturesList(self):
        return self.features
