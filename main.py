import requests


def ipfindin():
    """finding ip by 3rd party"""
    return requests.get('http://ip.42.pl/raw').text


