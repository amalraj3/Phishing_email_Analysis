# Phishing_email_Analysis
📄 Project Overview

This repository contains the detailed analysis of a phishing email impersonating Microsoft. The goal of this investigation is to dissect the email using industry-standard tools and present technical evidence confirming it as a credential theft attempt.

🕵️‍♂️ **Investigation Summary** 

Attack Type: Credential Phishing

Targeted Brand: Microsoft

Sender Address: no-reply@access-accsecurity.com (Domain not registered)

Reply-To Address: solutionteamrecognizd02@gmail.com (Freeservice, suspicious)

Impersonation Method: Fake Microsoft security alert email claiming unusual login activity.

Goal: Trick users into providing their account credentials.


🔧 **Tools Used**

  Sublime Security EML Analyzer
  
  WHOIS Lookup
  
  VirusTotal URL Scanner



📊 **Evidence Collected :**

1️⃣ EML Analyzer Output

  Verdict: Malicious

Detected:

  -Brand impersonation (Microsoft)
  
  -Credential phishing indicators
  
  -Suspicious, unregistered sender domain access-accsecurity.com
  
  -Attached Screenshot: Screenshot_eml_analyzer.png

2️⃣ WHOIS Lookup

  -Domain access-accsecurity.com is not registered, confirming forged sender.

3️⃣ Email Body Example

 - Mimics Microsoft account alerts.
  
  - Claims sign-in from Russia, IP: 103.225.77.255
  
  - Encourages clicking "Report the User" via suspicious links.
  
  - Attached Screenshot: Screenshot_eml_generated.png

4️⃣ VirusTotal Results

  - AWS-hosted link used in the email flagged by:
  
  - CRDF: Malicious
  
  - Phishing Database: Phishing
  
  - Attached Screenshot: Screenshot_virus_total.png

🔒 Conclusion

  This email is a textbook phishing attempt exploiting:
  
  - Fake security alerts.
  
  - Unregistered or spoofed domains.
  
  - Urgent, manipulative language.

  - Links flagged by known phishing databases.

❗Users are advised to:  
✔ Report such emails to security teams immediately  
✔ Avoid interacting with links or attachments  
✔ Educate end-users about verifying sender domains and email headers

