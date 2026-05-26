"""SEPSES namespace constants used by the Python RDF mapper.

The URIs follow the original sepses/cyber-kg-converter vocabulary style:
- http://w3id.org/sepses/vocab/ref/capec#
- http://w3id.org/sepses/vocab/ref/attack#
- http://w3id.org/sepses/vocab/ref/icsa#
- http://w3id.org/sepses/resource/{source}/...
"""

from rdflib import Namespace

RDF_RESOURCE = Namespace("http://w3id.org/sepses/resource/")
CAPEC = Namespace("http://w3id.org/sepses/vocab/ref/capec#")
ATTACK = Namespace("http://w3id.org/sepses/vocab/ref/attack#")
ICSA = Namespace("http://w3id.org/sepses/vocab/ref/icsa#")
CVE = Namespace("http://w3id.org/sepses/vocab/ref/cve#")
CWE = Namespace("http://w3id.org/sepses/vocab/ref/cwe#")
CPE = Namespace("http://w3id.org/sepses/vocab/ref/cpe#")
DCTERMS = Namespace("http://purl.org/dc/terms/")
XSD = Namespace("http://www.w3.org/2001/XMLSchema#")
