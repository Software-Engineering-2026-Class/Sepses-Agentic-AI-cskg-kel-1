# Contoh Input Raw Data & Output RDF per Datasource

Dokumen ini menjelaskan **format data mentah** dari masing-masing sumber cybersecurity yang digunakan dalam pipeline SEPSES CSKG, beserta **contoh output RDF/Turtle** yang dihasilkan setelah proses transformasi oleh pipeline.

Setiap contoh menunjukkan:
1. **Input Raw** — potongan representatif data asli dari sumber
2. **Penjelasan Field** — makna setiap field penting
3. **Output RDF/Turtle** — hasil transformasi ke triple RDF menggunakan ontologi SEPSES
4. **Penjelasan Mapping** — bagaimana field input dipetakan ke triple RDF

---

## Daftar Datasource

| Datasource | Format Input | Ontologi Namespace | Contoh |
|---|---|---|---|
| [CVE/CVSS (NVD)](#1-cvecvss-nvd) | JSON (NVD API 2.0) | `cyber:CVE` | 20 triple |
| [CWE](#2-cwe-common-weakness-enumeration) | XML (MITRE Catalogue) | `cyber:CWE` | 15 triple |
| [CPE](#3-cpe-common-platform-enumeration) | JSON (NVD API 2.0) | `cyber:CPE` | 15 triple |
| [CAPEC](#4-capec-common-attack-pattern) | XML (MITRE) | `cyber:CAPEC` | 15 triple |
| [MITRE ATT&CK](#5-mitre-attck) | STIX JSON Bundle | `cyber:Technique` | 20 triple |
| [ICSA Advisories](#6-icsa-ics-cert-advisories) | JSON (CISA) | `cyber:ICSAdvisory` | 15 triple |

**Prefix Namespace yang digunakan:**
```turtle
@prefix cyber: <http://w3id.org/sepses/vocab/ref/> .
@prefix cvss:  <http://w3id.org/sepses/vocab/ref/cvss/> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
@prefix rdfs:  <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl:   <http://www.w3.org/2002/07/owl#> .
```

---

## 1. CVE/CVSS (NVD)

**Sumber**: National Vulnerability Database (NVD) API 2.0  
**URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0`  
**Format**: JSON  
**Direktori Output Raw**: `data/raw/nvd/`

### 1.1 Input Raw (NVD API JSON)

Berikut contoh satu record CVE dari NVD API 2.0:

```json
{
  "id": "CVE-2023-44487",
  "sourceIdentifier": "cve@mitre.org",
  "published": "2023-10-10T14:15:10.043",
  "lastModified": "2024-01-21T02:16:16.850",
  "vulnStatus": "Analyzed",
  "descriptions": [
    {
      "lang": "en",
      "value": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023."
    }
  ],
  "metrics": {
    "cvssMetricV31": [
      {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
          "version": "3.1",
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          "baseScore": 7.5,
          "baseSeverity": "HIGH",
          "attackVector": "NETWORK",
          "attackComplexity": "LOW",
          "privilegesRequired": "NONE",
          "userInteraction": "NONE",
          "scope": "UNCHANGED",
          "confidentialityImpact": "NONE",
          "integrityImpact": "NONE",
          "availabilityImpact": "HIGH"
        },
        "exploitabilityScore": 3.9,
        "impactScore": 3.6
      }
    ]
  },
  "weaknesses": [
    {
      "source": "nvd@nist.gov",
      "type": "Primary",
      "description": [
        { "lang": "en", "value": "CWE-400" }
      ]
    }
  ],
  "configurations": [
    {
      "nodes": [
        {
          "operator": "OR",
          "cpeMatch": [
            {
              "vulnerable": true,
              "criteria": "cpe:2.3:a:ietf:http:2.0:*:*:*:*:*:*:*",
              "matchCriteriaId": "2D09D545-6E1A-4F5A-A3D2-6B4E5C2D3F1A"
            }
          ]
        }
      ]
    }
  ]
}
```

### 1.2 Penjelasan Field Kunci

| Field NVD | Tipe | Makna |
|---|---|---|
| `id` | string | ID unik CVE (format: CVE-YYYY-NNNNN) |
| `published` | datetime | Tanggal CVE dipublikasikan |
| `lastModified` | datetime | Tanggal modifikasi terakhir |
| `vulnStatus` | string | Status analisis (Analyzed, Modified, dll.) |
| `descriptions[].value` | string | Deskripsi kerentanan dalam bahasa Inggris |
| `metrics.cvssMetricV31[].cvssData.baseScore` | float | Skor CVSS 3.1 (0.0–10.0) |
| `metrics.cvssMetricV31[].cvssData.baseSeverity` | string | Tingkat keparahan (LOW/MEDIUM/HIGH/CRITICAL) |
| `metrics.cvssMetricV31[].cvssData.vectorString` | string | String vektor CVSS lengkap |
| `metrics.cvssMetricV31[].cvssData.attackVector` | string | Vektor serangan (NETWORK/ADJACENT/LOCAL/PHYSICAL) |
| `weaknesses[].description[].value` | string | ID CWE terkait |
| `configurations[].nodes[].cpeMatch[].criteria` | string | CPE yang terpengaruh |

### 1.3 Output RDF/Turtle

```turtle
@prefix cyber: <http://w3id.org/sepses/vocab/ref/> .
@prefix cvss:  <http://w3id.org/sepses/vocab/ref/cvss/> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
@prefix rdfs:  <http://www.w3.org/2000/01/rdf-schema#> .

# === ENTITAS CVE ===
<http://w3id.org/sepses/id/cve/CVE-2023-44487>
    a cyber:CVE ;
    rdfs:label "CVE-2023-44487" ;
    cyber:cveId "CVE-2023-44487" ;
    cyber:publishedDate "2023-10-10T14:15:10"^^xsd:dateTime ;
    cyber:modifiedDate "2024-01-21T02:16:16"^^xsd:dateTime ;
    cyber:vulnStatus "Analyzed" ;
    cyber:description "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023."@en ;

    # Relasi ke CVSS
    cyber:hasCVSS <http://w3id.org/sepses/id/cvss/CVE-2023-44487-v31> ;

    # Relasi ke CWE
    cyber:hasCWE <http://w3id.org/sepses/id/cwe/CWE-400> ;

    # Relasi ke CPE (platform yang rentan)
    cyber:affectsCPE <http://w3id.org/sepses/id/cpe/cpe:2.3:a:ietf:http:2.0> .

# === ENTITAS CVSS ===
<http://w3id.org/sepses/id/cvss/CVE-2023-44487-v31>
    a cvss:CVSS31 ;
    cvss:baseScore "7.5"^^xsd:decimal ;
    cvss:baseSeverity "HIGH" ;
    cvss:vectorString "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" ;
    cvss:attackVector "NETWORK" ;
    cvss:attackComplexity "LOW" ;
    cvss:privilegesRequired "NONE" ;
    cvss:userInteraction "NONE" ;
    cvss:scope "UNCHANGED" ;
    cvss:confidentialityImpact "NONE" ;
    cvss:integrityImpact "NONE" ;
    cvss:availabilityImpact "HIGH" ;
    cvss:exploitabilityScore "3.9"^^xsd:decimal ;
    cvss:impactScore "3.6"^^xsd:decimal .
```

### 1.4 Penjelasan Mapping

```
NVD JSON                          →  RDF Triple
─────────────────────────────────────────────────────────────────────────
id                                →  cyber:cveId + URI subject
published                         →  cyber:publishedDate (xsd:dateTime)
lastModified                      →  cyber:modifiedDate (xsd:dateTime)
vulnStatus                        →  cyber:vulnStatus
descriptions[lang=en].value       →  cyber:description (lang tag @en)
cvssData.baseScore                →  cvss:baseScore (xsd:decimal)
cvssData.baseSeverity             →  cvss:baseSeverity
cvssData.vectorString             →  cvss:vectorString
cvssData.attackVector             →  cvss:attackVector
weaknesses[].description[].value  →  cyber:hasCWE (relasi ke entitas CWE)
cpeMatch[].criteria               →  cyber:affectsCPE (relasi ke CPE)
```

**Total triple dari contoh ini: 20 triple**

---

## 2. CWE (Common Weakness Enumeration)

**Sumber**: MITRE CWE XML Catalogue  
**URL**: `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip`  
**Format**: XML  
**Direktori Output Raw**: `data/raw/cwe/`

### 2.1 Input Raw (XML MITRE)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"
                  Name="CWE" Version="4.13" Date="2024-02-29">
  <Weaknesses>
    <Weakness ID="400" Name="Uncontrolled Resource Consumption"
              Abstraction="Class" Structure="Simple" Status="Stable">
      <Description>
        The product does not properly control the allocation and
        maintenance of a limited resource, thereby enabling an actor
        to influence the amount of resources consumed, eventually
        leading to the exhaustion of available resources.
      </Description>
      <Extended_Description>
        Resource exhaustion attacks do not necessarily involve
        flooding the target with requests.
      </Extended_Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="664" View_ID="1000"/>
        <Related_Weakness Nature="ChildOf" CWE_ID="691" View_ID="1003"/>
      </Related_Weaknesses>
      <Applicable_Platforms>
        <Language Name="Not Language-Specific" Prevalence="Undetermined"/>
      </Applicable_Platforms>
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="OWASP Top Ten 2004">
          <Entry_ID>A9</Entry_ID>
          <Entry_Name>Denial of Service</Entry_Name>
          <Mapping_Fit>Exact</Mapping_Fit>
        </Taxonomy_Mapping>
      </Taxonomy_Mappings>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
```

### 2.2 Penjelasan Field Kunci

| Atribut/Elemen XML | Makna |
|---|---|
| `Weakness/@ID` | ID unik CWE (tanpa prefix "CWE-") |
| `Weakness/@Name` | Nama resmi kelemahan |
| `Weakness/@Abstraction` | Level abstraksi (Pillar/Class/Base/Variant) |
| `Weakness/@Status` | Status (Stable/Draft/Incomplete) |
| `Description` | Deskripsi singkat kelemahan |
| `Extended_Description` | Penjelasan tambahan |
| `Related_Weaknesses/Related_Weakness/@Nature` | Tipe relasi (ChildOf/ParentOf/PeerOf) |
| `Related_Weaknesses/Related_Weakness/@CWE_ID` | ID CWE yang berelasi |

### 2.3 Output RDF/Turtle

```turtle
@prefix cyber: <http://w3id.org/sepses/vocab/ref/> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
@prefix rdfs:  <http://www.w3.org/2000/01/rdf-schema#> .

# === ENTITAS CWE ===
<http://w3id.org/sepses/id/cwe/CWE-400>
    a cyber:CWE ;
    rdfs:label "CWE-400: Uncontrolled Resource Consumption" ;
    cyber:cweId "CWE-400" ;
    cyber:cweName "Uncontrolled Resource Consumption" ;
    cyber:abstraction "Class" ;
    cyber:status "Stable" ;
    cyber:description "The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources."@en ;

    # Relasi hierarki CWE
    cyber:isChildOf <http://w3id.org/sepses/id/cwe/CWE-664> ;
    cyber:isChildOf <http://w3id.org/sepses/id/cwe/CWE-691> .

# CWE parent (referensi)
<http://w3id.org/sepses/id/cwe/CWE-664>
    a cyber:CWE ;
    cyber:cweId "CWE-664" .

<http://w3id.org/sepses/id/cwe/CWE-691>
    a cyber:CWE ;
    cyber:cweId "CWE-691" .
```

### 2.4 Penjelasan Mapping

```
XML Attribute/Element                  →  RDF Triple
─────────────────────────────────────────────────────────────────────────
Weakness/@ID                           →  cyber:cweId + URI subject
Weakness/@Name                         →  cyber:cweName + rdfs:label
Weakness/@Abstraction                  →  cyber:abstraction
Weakness/@Status                       →  cyber:status
Description (text)                     →  cyber:description (@en)
Related_Weakness[@Nature="ChildOf"]    →  cyber:isChildOf (relasi ke CWE lain)
Related_Weakness[@Nature="ParentOf"]   →  cyber:isParentOf
```

**Total triple dari contoh ini: 15 triple**

---

## 3. CPE (Common Platform Enumeration)

**Sumber**: NVD CPE Dictionary API 2.0  
**URL**: `https://services.nvd.nist.gov/rest/json/cpes/2.0`  
**Format**: JSON  
**Direktori Output Raw**: `data/raw/cpe/`

### 3.1 Input Raw (NVD API JSON)

```json
{
  "cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
  "cpeNameId": "7B3DB0DB-7F3E-4B32-891B-1B9A06DB2D56",
  "lastModified": "2023-03-28T13:02:41.830",
  "created": "2021-12-16T18:26:41.660",
  "titles": [
    {
      "title": "Apache Log4j 2.14.1",
      "lang": "en"
    }
  ],
  "refs": [
    {
      "ref": "https://logging.apache.org/log4j/2.x/",
      "type": "Product"
    }
  ],
  "deprecated": false,
  "deprecatedBy": []
}
```

### 3.2 Penjelasan Field Kunci

| Field NVD CPE | Makna |
|---|---|
| `cpeName` | String CPE 2.3 lengkap (format: `cpe:2.3:part:vendor:product:version:...`) |
| `cpeNameId` | UUID unik untuk entri CPE ini |
| `titles[].title` | Nama produk yang mudah dibaca manusia |
| `created` | Tanggal CPE ditambahkan ke dictionary |
| `lastModified` | Tanggal modifikasi terakhir |
| `deprecated` | Apakah CPE ini sudah tidak aktif |
| `refs[].ref` | URL referensi produk |

**Struktur CPE 2.3**: `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`
- `part`: `a` = application, `o` = OS, `h` = hardware
- `*` = any value

### 3.3 Output RDF/Turtle

```turtle
@prefix cyber: <http://w3id.org/sepses/vocab/ref/> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
@prefix rdfs:  <http://www.w3.org/2000/01/rdf-schema#> .

# === ENTITAS CPE ===
<http://w3id.org/sepses/id/cpe/cpe:2.3:a:apache:log4j:2.14.1>
    a cyber:CPE ;
    rdfs:label "Apache Log4j 2.14.1" ;
    cyber:cpeName "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" ;
    cyber:cpeNameId "7B3DB0DB-7F3E-4B32-891B-1B9A06DB2D56" ;
    cyber:cpeVendor "apache" ;
    cyber:cpeProduct "log4j" ;
    cyber:cpeVersion "2.14.1" ;
    cyber:cpePart "a" ;
    cyber:title "Apache Log4j 2.14.1"@en ;
    cyber:created "2021-12-16T18:26:41"^^xsd:dateTime ;
    cyber:lastModified "2023-03-28T13:02:41"^^xsd:dateTime ;
    cyber:deprecated "false"^^xsd:boolean ;
    cyber:referenceURL "https://logging.apache.org/log4j/2.x/"^^xsd:anyURI .
```

### 3.4 Penjelasan Mapping

```
NVD CPE JSON field      →  RDF Triple
──────────────────────────────────────────────────────
cpeName                 →  cyber:cpeName + URI subject (parsed komponen)
cpeNameId               →  cyber:cpeNameId
titles[lang=en].title   →  rdfs:label + cyber:title (@en)
created                 →  cyber:created (xsd:dateTime)
lastModified            →  cyber:lastModified (xsd:dateTime)
deprecated              →  cyber:deprecated (xsd:boolean)
refs[type=Product].ref  →  cyber:referenceURL (xsd:anyURI)
[parsed] vendor         →  cyber:cpeVendor
[parsed] product        →  cyber:cpeProduct
[parsed] version        →  cyber:cpeVersion
[parsed] part           →  cyber:cpePart
```

**Total triple dari contoh ini: 13 triple**

---

## 4. CAPEC (Common Attack Pattern Enumeration)

**Sumber**: MITRE CAPEC XML  
**URL**: `https://capec.mitre.org/data/xml/capec_latest.xml`  
**Format**: XML  
**Direktori Output Raw**: `data/raw/capec/`

### 4.1 Input Raw (XML MITRE)

```xml
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3"
                        Name="CAPEC" Version="3.9" Date="2023-07-31">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection"
                    Abstraction="Meta" Status="Stable">
      <Description>
        This attack exploits target software that constructs SQL statements
        based on user input. An attacker crafts input strings so that when
        the target software constructs SQL statements based on the input,
        the resulting SQL statement performs actions other than those
        the application intended.
      </Description>
      <Likelihood_Of_Attack>High</Likelihood_Of_Attack>
      <Typical_Severity>High</Typical_Severity>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="248"/>
        <Related_Attack_Pattern Nature="ParentOf" CAPEC_ID="7"/>
        <Related_Attack_Pattern Nature="ParentOf" CAPEC_ID="110"/>
      </Related_Attack_Patterns>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89"/>
        <Related_Weakness CWE_ID="1286"/>
      </Related_Weaknesses>
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="ATTACK">
          <Entry_ID>T1190</Entry_ID>
          <Entry_Name>Exploit Public-Facing Application</Entry_Name>
        </Taxonomy_Mapping>
      </Taxonomy_Mappings>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
```

### 4.2 Penjelasan Field Kunci

| Atribut/Elemen XML | Makna |
|---|---|
| `Attack_Pattern/@ID` | ID unik CAPEC |
| `Attack_Pattern/@Name` | Nama pola serangan |
| `Attack_Pattern/@Abstraction` | Level abstraksi (Meta/Standard/Detailed) |
| `Description` | Deskripsi pola serangan |
| `Likelihood_Of_Attack` | Kemungkinan serangan (High/Medium/Low) |
| `Typical_Severity` | Keparahan tipikal |
| `Related_Attack_Pattern/@Nature` | Tipe relasi antar CAPEC |
| `Related_Weakness/@CWE_ID` | CWE yang berkaitan dengan CAPEC ini |
| `Taxonomy_Mapping[ATTACK]/Entry_ID` | ID teknik MITRE ATT&CK yang setara |

### 4.3 Output RDF/Turtle

```turtle
@prefix cyber: <http://w3id.org/sepses/vocab/ref/> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
@prefix rdfs:  <http://www.w3.org/2000/01/rdf-schema#> .

# === ENTITAS CAPEC ===
<http://w3id.org/sepses/id/capec/CAPEC-66>
    a cyber:CAPEC ;
    rdfs:label "CAPEC-66: SQL Injection" ;
    cyber:capecId "CAPEC-66" ;
    cyber:capecName "SQL Injection" ;
    cyber:abstraction "Meta" ;
    cyber:status "Stable" ;
    cyber:description "This attack exploits target software that constructs SQL statements based on user input. An attacker crafts input strings so that when the target software constructs SQL statements based on the input, the resulting SQL statement performs actions other than those the application intended."@en ;
    cyber:likelihoodOfAttack "High" ;
    cyber:typicalSeverity "High" ;

    # Relasi hierarki CAPEC
    cyber:isChildOf  <http://w3id.org/sepses/id/capec/CAPEC-248> ;
    cyber:isParentOf <http://w3id.org/sepses/id/capec/CAPEC-7> ;
    cyber:isParentOf <http://w3id.org/sepses/id/capec/CAPEC-110> ;

    # Relasi ke CWE yang dieksploitasi
    cyber:exploitsCWE <http://w3id.org/sepses/id/cwe/CWE-89> ;
    cyber:exploitsCWE <http://w3id.org/sepses/id/cwe/CWE-1286> ;

    # Relasi cross-mapping ke MITRE ATT&CK
    cyber:mappedToTechnique <http://w3id.org/sepses/id/attack/T1190> .
```

### 4.4 Penjelasan Mapping

```
XML Attribute/Element                        →  RDF Triple
─────────────────────────────────────────────────────────────────────────────
Attack_Pattern/@ID                           →  cyber:capecId + URI subject
Attack_Pattern/@Name                         →  cyber:capecName + rdfs:label
Attack_Pattern/@Abstraction                  →  cyber:abstraction
Likelihood_Of_Attack (text)                  →  cyber:likelihoodOfAttack
Typical_Severity (text)                      →  cyber:typicalSeverity
Description (text)                           →  cyber:description (@en)
Related_Attack_Pattern[@Nature="ChildOf"]    →  cyber:isChildOf
Related_Attack_Pattern[@Nature="ParentOf"]   →  cyber:isParentOf
Related_Weakness/@CWE_ID                     →  cyber:exploitsCWE
Taxonomy_Mapping[ATTACK]/Entry_ID            →  cyber:mappedToTechnique
```

**Total triple dari contoh ini: 15 triple**

---

## 5. MITRE ATT&CK

**Sumber**: MITRE ATT&CK STIX Repository  
**URL**: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`  
**Format**: STIX 2.0 JSON Bundle  
**Direktori Output Raw**: `data/raw/attack/`  
**Koleksi**: Enterprise ATT&CK + ICS ATT&CK

### 5.1 Input Raw (STIX 2.0 JSON)

```json
{
  "type": "bundle",
  "id": "bundle--535be4c1-5a98-4e20-a5af-9d17e4c50c00",
  "spec_version": "2.0",
  "objects": [
    {
      "type": "attack-pattern",
      "id": "attack-pattern--be2dcee9-a7a7-4e38-afd6-21b31ecc3d63",
      "created": "2020-10-01T01:22:18.368Z",
      "modified": "2023-10-04T17:59:03.066Z",
      "name": "Exploit Public-Facing Application",
      "description": "Adversaries may attempt to exploit weakness in an Internet-facing host or system to initially access a network.",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "initial-access"
        }
      ],
      "external_references": [
        {
          "source_name": "mitre-attack",
          "url": "https://attack.mitre.org/techniques/T1190",
          "external_id": "T1190"
        }
      ],
      "x_mitre_platforms": ["Windows", "Linux", "macOS", "Network", "Containers"],
      "x_mitre_is_subtechnique": false,
      "x_mitre_detection": "Monitor application logs for abnormal behavior...",
      "x_mitre_data_sources": ["Network Traffic: Network Traffic Content"],
      "x_mitre_impact_type": ["Availability"],
      "revoked": false
    }
  ]
}
```

### 5.2 Penjelasan Field Kunci

| Field STIX | Makna |
|---|---|
| `type` | Tipe objek STIX (attack-pattern, malware, tool, dll.) |
| `id` | STIX UUID object |
| `name` | Nama teknik ATT&CK |
| `description` | Deskripsi teknik serangan |
| `kill_chain_phases[].phase_name` | Fase taktik (initial-access, execution, dll.) |
| `external_references[source=mitre-attack].external_id` | ID teknik resmi (T1190) |
| `x_mitre_platforms` | Platform yang ditargetkan |
| `x_mitre_is_subtechnique` | Apakah ini sub-teknik (true = T1190.001) |
| `x_mitre_detection` | Panduan deteksi |
| `revoked` | Apakah teknik ini sudah dicabut |

### 5.3 Output RDF/Turtle

```turtle
@prefix cyber: <http://w3id.org/sepses/vocab/ref/> .
@prefix attack: <http://w3id.org/sepses/vocab/ref/attack/> .
@prefix xsd:    <http://www.w3.org/2001/XMLSchema#> .
@prefix rdfs:   <http://www.w3.org/2000/01/rdf-schema#> .

# === ENTITAS MITRE ATT&CK TECHNIQUE ===
<http://w3id.org/sepses/id/attack/T1190>
    a cyber:Technique ;
    rdfs:label "T1190: Exploit Public-Facing Application" ;
    attack:techniqueId "T1190" ;
    attack:stixId "attack-pattern--be2dcee9-a7a7-4e38-afd6-21b31ecc3d63" ;
    cyber:name "Exploit Public-Facing Application" ;
    cyber:description "Adversaries may attempt to exploit weakness in an Internet-facing host or system to initially access a network."@en ;
    attack:created "2020-10-01T01:22:18"^^xsd:dateTime ;
    attack:modified "2023-10-04T17:59:03"^^xsd:dateTime ;
    attack:isSubtechnique "false"^^xsd:boolean ;
    attack:revoked "false"^^xsd:boolean ;

    # Fase taktik (kill chain)
    attack:hasTactic <http://w3id.org/sepses/id/attack/tactic/initial-access> ;

    # Platform
    attack:platform "Windows" ;
    attack:platform "Linux" ;
    attack:platform "macOS" ;
    attack:platform "Network" ;
    attack:platform "Containers" ;

    # Referensi URL
    cyber:referenceURL "https://attack.mitre.org/techniques/T1190"^^xsd:anyURI .

# === ENTITAS TAKTIK ===
<http://w3id.org/sepses/id/attack/tactic/initial-access>
    a attack:Tactic ;
    rdfs:label "Initial Access" ;
    attack:tacticName "initial-access" .
```

### 5.4 Penjelasan Mapping

```
STIX JSON field                                    →  RDF Triple
───────────────────────────────────────────────────────────────────────────────
external_references[mitre-attack].external_id      →  attack:techniqueId + URI
id (STIX UUID)                                     →  attack:stixId
name                                               →  cyber:name + rdfs:label
description                                        →  cyber:description (@en)
created                                            →  attack:created (xsd:dateTime)
modified                                           →  attack:modified (xsd:dateTime)
kill_chain_phases[].phase_name                     →  attack:hasTactic → Tactic URI
x_mitre_platforms[]                                →  attack:platform (multi-value)
x_mitre_is_subtechnique                            →  attack:isSubtechnique (xsd:boolean)
revoked                                            →  attack:revoked (xsd:boolean)
external_references[mitre-attack].url              →  cyber:referenceURL (xsd:anyURI)
```

**Total triple dari contoh ini: 20 triple**

---

## 6. ICSA (ICS-CERT Advisories)

**Sumber**: CISA ICS Advisories  
**URL**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`  
**Format**: JSON  
**Direktori Output Raw**: `data/raw/icsa/`

### 6.1 Input Raw (CISA JSON)

```json
{
  "advisoryId": "ICSA-23-320-01",
  "title": "Siemens SCALANCE W1750D",
  "vendor": "Siemens",
  "product": "SCALANCE W1750D",
  "releaseDate": "2023-11-16",
  "lastUpdated": "2023-11-16",
  "summary": "Successful exploitation of these vulnerabilities could allow a remote attacker to obtain sensitive information, execute code or command injection, or cause a denial of service condition.",
  "severity": "CRITICAL",
  "cvssScore": 9.8,
  "cves": ["CVE-2023-22440", "CVE-2023-22441"],
  "cwes": ["CWE-120", "CWE-78"],
  "affectedProducts": [
    {
      "vendor": "Siemens",
      "productName": "SCALANCE W1750D",
      "versionRange": "< V8.10.0.1"
    }
  ],
  "sector": "Critical Manufacturing",
  "country": "Global",
  "mitigations": "Siemens has released updates to resolve these vulnerabilities.",
  "advisoryUrl": "https://www.cisa.gov/news-events/ics-advisories/icsa-23-320-01"
}
```

### 6.2 Penjelasan Field Kunci

| Field ICSA | Makna |
|---|---|
| `advisoryId` | ID unik advisory (format: ICSA-YY-DDD-NN) |
| `title` | Judul advisory (biasanya nama vendor + produk) |
| `vendor` | Vendor/pabrikan perangkat yang terpengaruh |
| `product` | Nama produk yang rentan |
| `releaseDate` | Tanggal advisory dirilis oleh CISA |
| `severity` | Tingkat keparahan (CRITICAL/HIGH/MEDIUM/LOW) |
| `cvssScore` | Skor CVSS keseluruhan advisory |
| `cves` | Daftar ID CVE yang dibahas |
| `cwes` | Tipe kelemahan yang dieksploitasi |
| `affectedProducts[].versionRange` | Range versi yang terpengaruh |
| `sector` | Sektor industri yang terpengaruh (ICS-specific) |

### 6.3 Output RDF/Turtle

```turtle
@prefix cyber: <http://w3id.org/sepses/vocab/ref/> .
@prefix icsa:  <http://w3id.org/sepses/vocab/ref/icsa/> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
@prefix rdfs:  <http://www.w3.org/2000/01/rdf-schema#> .

# === ENTITAS ICSA ADVISORY ===
<http://w3id.org/sepses/id/icsa/ICSA-23-320-01>
    a cyber:ICSAdvisory ;
    rdfs:label "ICSA-23-320-01: Siemens SCALANCE W1750D" ;
    icsa:advisoryId "ICSA-23-320-01" ;
    icsa:title "Siemens SCALANCE W1750D" ;
    icsa:vendor "Siemens" ;
    icsa:product "SCALANCE W1750D" ;
    icsa:releaseDate "2023-11-16"^^xsd:date ;
    icsa:lastUpdated "2023-11-16"^^xsd:date ;
    icsa:severity "CRITICAL" ;
    icsa:cvssScore "9.8"^^xsd:decimal ;
    icsa:sector "Critical Manufacturing" ;
    icsa:summary "Successful exploitation of these vulnerabilities could allow a remote attacker to obtain sensitive information, execute code or command injection, or cause a denial of service condition."@en ;
    icsa:mitigations "Siemens has released updates to resolve these vulnerabilities."@en ;
    cyber:referenceURL "https://www.cisa.gov/news-events/ics-advisories/icsa-23-320-01"^^xsd:anyURI ;

    # Relasi ke CVE yang dibahas
    cyber:referencesCVE <http://w3id.org/sepses/id/cve/CVE-2023-22440> ;
    cyber:referencesCVE <http://w3id.org/sepses/id/cve/CVE-2023-22441> ;

    # Relasi ke CWE
    cyber:exploitsCWE <http://w3id.org/sepses/id/cwe/CWE-120> ;
    cyber:exploitsCWE <http://w3id.org/sepses/id/cwe/CWE-78> .
```

### 6.4 Penjelasan Mapping

```
ICSA JSON field              →  RDF Triple
────────────────────────────────────────────────────────────
advisoryId                   →  icsa:advisoryId + URI subject
title                        →  icsa:title + rdfs:label
vendor                       →  icsa:vendor
product                      →  icsa:product
releaseDate                  →  icsa:releaseDate (xsd:date)
lastUpdated                  →  icsa:lastUpdated (xsd:date)
severity                     →  icsa:severity
cvssScore                    →  icsa:cvssScore (xsd:decimal)
sector                       →  icsa:sector
summary                      →  icsa:summary (@en)
mitigations                  →  icsa:mitigations (@en)
advisoryUrl                  →  cyber:referenceURL (xsd:anyURI)
cves[]                       →  cyber:referencesCVE (relasi ke CVE)
cwes[]                       →  cyber:exploitsCWE (relasi ke CWE)
```

**Total triple dari contoh ini: 17 triple**

---

## Ringkasan Statistik Contoh

| Datasource | Format Input | Triple RDF | Relasi Lintas-Sumber |
|---|---|---|---|
| CVE/CVSS (NVD) | JSON | 20 | → CWE, CPE |
| CWE | XML | 15 | → CWE (parent/child) |
| CPE | JSON | 13 | - |
| CAPEC | XML | 15 | → CWE, ATT&CK |
| MITRE ATT&CK | STIX JSON | 20 | → Tactic |
| ICSA | JSON | 17 | → CVE, CWE |
| **Total** | | **100 triple** | |

## Gambaran Hubungan Antar-Entitas

```
CVE ──────hasCVSS──────► CVSS Score
 │
 ├────hasCWE───────────► CWE ◄──────exploitsCWE──── CAPEC
 │                        │                            │
 ├────affectsCPE────────► CPE          isChildOf       │
 │                                         │           │
 └────referencesCVE◄──── ICSA         CWE (parent)  mappedToTechnique
                                                         │
                                                         ▼
                                                    ATT&CK Technique
                                                         │
                                                    hasTactic
                                                         │
                                                         ▼
                                                       Tactic
```

## Cara Menggunakan Contoh di QLever UI

Setelah QLever endpoint berjalan (`http://localhost:7001/sparql`) dan UI aktif (`http://localhost:7000`), Anda bisa langsung query:

```sparql
# Contoh: Semua CVE dengan skor CVSS >= 9.0
PREFIX cyber: <http://w3id.org/sepses/vocab/ref/>
PREFIX cvss:  <http://w3id.org/sepses/vocab/ref/cvss/>
PREFIX xsd:   <http://www.w3.org/2001/XMLSchema#>

SELECT ?cve ?score ?severity WHERE {
  ?cve a cyber:CVE ;
       cyber:hasCVSS ?cvssNode .
  ?cvssNode cvss:baseScore ?score ;
            cvss:baseSeverity ?severity .
  FILTER(?score >= 9.0)
}
ORDER BY DESC(?score)
LIMIT 20
```

```sparql
# Contoh: CVE yang terkait dengan CWE-400 (Uncontrolled Resource Consumption)
PREFIX cyber: <http://w3id.org/sepses/vocab/ref/>

SELECT ?cve ?desc WHERE {
  ?cve a cyber:CVE ;
       cyber:hasCWE <http://w3id.org/sepses/id/cwe/CWE-400> ;
       cyber:description ?desc .
}
LIMIT 10
```

```sparql
# Contoh: Teknik ATT&CK yang bisa digunakan untuk mengeksploitasi CWE-89 via CAPEC
PREFIX cyber: <http://w3id.org/sepses/vocab/ref/>

SELECT ?capec ?technique WHERE {
  ?capec a cyber:CAPEC ;
         cyber:exploitsCWE <http://w3id.org/sepses/id/cwe/CWE-89> ;
         cyber:mappedToTechnique ?technique .
}
```
