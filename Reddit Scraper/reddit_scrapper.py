[
  {
    "cves": [
      "CVE-2023-42007"
    ],
    "cve_counts": {
      "CVE-2023-42007": 1
    },
    "title": "CVE Alert: CVE-2023-42007",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jwm1kz/cve_alert_cve202342007/",
    "timestamp": "2025-04-11T11:50:14",
    "article_text": "IBM Sterling Control Center 6.2.1, 6.3.1, and 6.4.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-22230"
    ],
    "cve_counts": {
      "CVE-2025-22230": 3
    },
    "title": "VMSA-2025-0005: VMware Tools for Windows update addresses an authentication bypass vulnerability (CVE-2025-22230)",
    "text": ">VMware Tools authentication bypass vulnerability (CVE-2025-22230)\n\n>Description:   \nVMware Tools for Windows contains an authentication bypass vulnerability due to improper access control. VMware has evaluated the severity of this issue to be in the [Important severity range](https://www.broadcom.com/support/vmware-services/security-response) with a maximum CVSSv3 base score of [7.8](https://www.first.org/cvss/calculator/3-1#CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).\n\n>Known Attack Vectors:  \nA malicious actor with non-administrative privileges on a Windows guest VM may gain ability to perform certain high-privilege operations within that VM.VMware Tools authentication bypass vulnerability (CVE-2025-22230)  \nDescription:   \nVMware Tools for Windows contains an authentication bypass vulnerability due to improper access control. VMware has evaluated the severity of this issue to be in the Important severity range with a maximum CVSSv3 base score of 7.8.  \nKnown Attack Vectors:  \nA malicious actor with non-administrative privileges on a Windows guest VM may gain ability to perform certain high-privilege operations within that VM.\n\nVMware Tools for **Windows only, Linux and Mac is not affected**\n\nI am very curious which \"high-privilege operations within that VM\" are meant by that VMSA. Maybe someone can give some insight on this?\n\nSource: [https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25518](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25518)\n\n  \n\\[Edit 2025-03-26\\]  \nHave asked [vmware.psirt@broadcom.com](mailto:vmware.psirt@broadcom.com) for more details on the \"high-privilege operations within that VM\" wording. The answer is clear: They won't give out any more details.",
    "permalink": "/r/vmware/comments/1jjkivb/vmsa20250005_vmware_tools_for_windows_update/",
    "timestamp": "2025-03-25T14:22:18",
    "article_text": null,
    "comments": [
      {
        "score": 22,
        "text": "Yippie more patching oh what fun!",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1,
      "cve-2025-29927": 1
    },
    "title": "Next.js Authentication Bypass Vulnerability (CVE-2025-29927) Explained Simply",
    "text": "I've created a beginner-friendly breakdown of this critical Next.js middleware vulnerability that affects millions of applications\n\nPlease take a look and let me know what you think 💭 \n\n📖 https://neoxs.me/blog/critical-nextjs-middleware-vulnerability-cve-2025-29927-authentication-bypass",
    "permalink": "/r/reactjs/comments/1ji309p/nextjs_authentication_bypass_vulnerability/",
    "timestamp": "2025-03-23T16:20:39",
    "article_text": null,
    "comments": [
      {
        "score": 16,
        "text": "Really good article on this, but your code snippet aren't scrollable on mobile.",
        "level": 0
      },
      {
        "score": 5,
        "text": "Thanks for your feedback i will improve it 🙏",
        "level": 1
      },
      {
        "score": 9,
        "text": "Some of them do appear to be scrollable, I think one of the list items is breaking scroll so the page size is larger than the browser window size.\n\nSite does look really good.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1
    },
    "title": "Next.js Middleware Exploit: Deep Dive into CVE-2025-29927 Authorization Bypass - ZeroPath Blog",
    "text": "",
    "permalink": "/r/programming/comments/1jhloj4/nextjs_middleware_exploit_deep_dive_into/",
    "timestamp": "2025-03-22T23:26:39",
    "article_text": null,
    "comments": [
      {
        "score": 169,
        "text": "A detailed approach to the research was published here: https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware.\n\nThis vulnerability is insane.",
        "level": 0
      },
      {
        "score": 38,
        "text": "Thank you, this is a way better link",
        "level": 1
      },
      {
        "score": -46,
        "text": "Not really. He's REALLY stretching the extent of the vulnerability. CSP is a client-side protection, nothing to do with the web app itself.\n\nYou cannot forge an identity or modify the _output_ of the middleware functions. This is merely a bypass of what should be a pretty superficial check in your overall application. \n\nIf this vulnerability _immediately_ affects you in a material way then you need to revaluate your entire architecture.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-9956"
    ],
    "cve_counts": {
      "CVE-2024-9956": 1
    },
    "title": "CVE-2024-9956 - PassKey Account Takeover in All Mobile Browsers",
    "text": "",
    "permalink": "/r/Bitwarden/comments/1jgtnt5/cve20249956_passkey_account_takeover_in_all/",
    "timestamp": "2025-03-21T22:39:52",
    "article_text": null,
    "comments": [
      {
        "score": 155,
        "text": "TLDR An attacker within bluetooth range is able to trigger navigation to a FIDO:/ URI from an attacker controlled page on a mobile browser, allowing them to initiate a legitimate PassKeys authentication intent which will be received on the attacker’s device. This results in the attacker being able to “phish” PassKeys credentials, completely breaking this assumption that PassKeys are impossible to phish.\n\n\nCool. So you have to be on the attacker’s ~~network~~ malicious website, in Bluetooth range of the attacker, and be on a mobile browser. \n\nSo, not really a big vulnerability, but a neat MITM attack.",
        "level": 0
      },
      {
        "score": 37,
        "text": "Or the attacker can be on YOUR network...  This, you'd better check your Wifi passwords and security protocols.\n\nI guess I shouldn't be doing this phone FIDO2 thing on other people's networks, or should be very cautious about it.",
        "level": 1
      },
      {
        "score": 22,
        "text": "Unless your wifi and admin panel password is the default one from the box, realistically this attack would have to be on either public wifi, or an highly targeted attack. And the common Joe isn’t really a high value target.",
        "level": 2
      },
      {
        "score": 13,
        "text": "> breaking this assumption that PassKeys are impossible to phish\n\nIt's still not extracting the private key - it's intercepting the signing of a single request.",
        "level": 1
      },
      {
        "score": 16,
        "text": "Same method as phishing an OTP. The secret is not compromised, but you can get the OTP from the user.",
        "level": 2
      },
      {
        "score": 4,
        "text": "Technically someone can set up a device like a Raspberry Pi close to a victim using it as a remote proxy. \n\nThey can then start a PassKey authentication via Bluetooth from anywhere effectively phishing PassKey credentials remotely. \n\nThis can allow attackers to take advantage of PassKeys from their own home even after leaving the device behind. \n\nWhile it’s still tricky and not something the average person has to worry about, this moves from a simple man-in-the-middle attack to a more complex and creative method to do it remotely.\n\nUpdate your browsers y’all!",
        "level": 1
      },
      {
        "score": 3,
        "text": "Why do you have to be on the same network? That isn't a requirement of CTAP AFAIK. You just need to be within bluetooth range of the attacker device (and on attacker site obviously to get FIDO: URI).",
        "level": 1
      },
      {
        "score": 2,
        "text": "Edited. You are correct. I was thinking of the easiest way to get a victim near you to a malicious website, and captive portals came to mind.",
        "level": 2
      },
      {
        "score": 1,
        "text": "Imagine being connected to a public WiFi, or on a plane. How is that not a big vulnerability?",
        "level": 1
      },
      {
        "score": 1,
        "text": "Or a public WiFi, according to the note with some phishing.\n\nAlso was fixed in some updates in October 2024. This is old news new that probably no one noticed until now, especially OP.",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-23120",
      "CVE-2024-29849"
    ],
    "cve_counts": {
      "CVE-2024-29849": 2,
      "CVE-2025-23120": 1
    },
    "title": "[PSA] Critical Veeam Vulnerability CVE-2024-29849",
    "text": "This one has a severity score of 9.9 so better patch fast:  \n[https://www.veeam.com/kb4696](https://www.veeam.com/kb4696)\n\n**EDIT: This vulnerability only impacts domain-joined backup servers.**\n\nThis refers to **CVE-2025-23120** and not CVE-2024-29849 as I mistakenly put in the subject, sorry about that!",
    "permalink": "/r/sysadmin/comments/1jf0luo/psa_critical_veeam_vulnerability_cve202429849/",
    "timestamp": "2025-03-19T16:09:04",
    "article_text": null,
    "comments": [
      {
        "score": 74,
        "text": "**Note:** This vulnerability only impacts domain-joined backup servers, which is against the [Security & Compliance Best Practices](https://helpcenter.veeam.com/docs/backup/vsphere/best_practices_analyzer.html?zoom_highlight=%22Backup%20server%20should%20not%20be%20a%20part%20of%20the%20production%20domain%22).",
        "level": 0
      },
      {
        "score": 15,
        "text": "I have a domain joined jump box running the Veeam console but the backup and replication service/database runs on a non domain joined server. Does this only impact servers running the backup and replication service, or even the console?",
        "level": 1
      },
      {
        "score": 10,
        "text": "That line is in the post on Veeam as well but it's not entirely accurate. The best practices aren't to have a server not domain joined but to have it in a management domain separate from production.",
        "level": 1
      },
      {
        "score": 7,
        "text": "Sorry, yes, I should have mentioned that.  I've edited the post accordingly.",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2020-14979"
    ],
    "cve_counts": {
      "cve-2020-14979": 2
    },
    "title": "Why does Defender hate Fan Control? An explanation of Windows Drivers, WinRing0.sys, and its 7.8 CVE score:",
    "text": "#TL;DR\n\n* Windows Defender is not wrong, per se. `WinRing0` DOES has a vulnerability that lets unprivileged programs *hack into Windows.\n* Fan Control is not malicious, `WinRing0` is not malicious, but a malicious program can use `WinRing0` to bypass your system's security measures because it has a vulnerability.\n* Read source 1 for the technical details.\n* You don't have to read this entire wall of text, skip to the headers that interests you.\n\n# Introduction\n\nHello everyone! As you probably found out by now, Fan Control's implementation is currently broken. This is due to the kernel driver that Fan Control uses `WinRing0` being blocked by Windows Defender.\n\nI want to clarify a few things I learned while researching this and show a bit of behind the scenes of how your computer talks to Fan Control and why Defender has blocked it.\n\n# Pet Peeve\n\nFirst off, as a computer scientist it pains me to see people's knee jerk reaction is to override their operating system's security systems. It's there to protect you, yes it can make mistakes, but you should generally wait for an official response or similar understanding and you shouldn't do it blindly. Your security means nothing if you override your security when it's inconvenient.\n\nIt's kind of like taking the carbon monoxide alarm off the wall because you don't like that it's beeping super loudly.\n\nAnyways.\n\n# What is a driver and why do we need them?\n^(skip to next header if you don't care how drivers work)\n\nTo answer why Defender has blocked fan Control, I first have to explain how Fan Control works with Windows. I'll try to keep this explanation as simple as possible. *^(Asterisks indicate an oversimplification for clarity)\n\nWindow's main job is to manage a bunch of different applications and allow them to talk to the hardware. In old times it used to be the case that a program can tell the computer to do whatever it wants. This was a problem because it could mess up other programs, crash the entire system, and do malicious things.\n\nSo to fix this, operating systems (OS) now split up the computer's memory and give a piece to each application. This application now has its own space to do things, called user-space. Each application is *only allowed to do things in its own piece of memory and nothing else. If the application crashed, the OS can throw away the application & its piece of memory and everything else on the system will be fine.\n\nThis has a big problem though: applications isolated in user-space could not talk to hardware! If you can talk to the hardware, you can do anything to the system, so it's an intentional protection. But your hardware needs to talk to the operating system to work, but there is too many pieces of hardware that all work differently. Windows doesn't know how to talk to all of them!\n\nSo we need these programs that can interface with hardware but can't live in user-space. But at the same time we want the kind of protection that user-space gives.\n\nThe solution is drivers: special programs that can receive special exceptions to live in *kernel-space. Kernel-space is the opposite of user-space. You can do anything in kernel-space! Like talk to hardware to control your fans or read your credit card number when you pay for something. Because kernel-space drivers are so high risk Microsoft gate keeps them with an iron fist, kinda like Apple's non-EU app store on iPhones.\n\n# Fan Control used a driver called `WinRing0`\n\nFan Control cannot talk directly to your hardware. It can talk to a driver, and that driver can talk to the hardware. There are a few different drivers and api's Fan Control uses, but the main one was `WinRing0`.\n\n### Who made `WinRing0`?\n\n`WinRing0` is a third party driver developed by OpenLibSys.\n\n### Who convinced Microsoft to let `WinRing0` be a driver with privileges?\n\nThe company called EVGA convinced Microsoft. Why? Because EVGA made software that used the third party driver. They don't use it anymore because it was vulnerable.\n\n# `WinRing0` is a vulnerable driver!\n\nThis is why Defender hates `WinRing0`.\n\nOn August 11th, 2020 a security researcher named Matt Hand published¹ the vulnerability report for `WinRing0` proving that it had a high-risk privilege escalation exploit. This means a user-space program can take control of this driver* and then use it to gain kernel-space privileges. This means a lowly application can take advantage of `WinRing0` to do whatever it wants to your computer!\n\nWhen this was discovered, EVGA abandoned `WinRing0` and made their own proprietary driver that they use. The developers of `WinRing0` can fix the driver, but under Microsoft's modern strict driver rules, an updated `WinRing0` won't make it past Microsoft's driver gate keepers.\n\nMany projects used and still use this driver. That's why Microsoft couldn't just cut support outright for the driver- too many things would break all at once. But `WinRing0` was on borrowed time, Microsoft planned to cut the driver in 2024, but then they pushed it back to Jan 2025. And now Microsoft seems to start following through.\n\n# What are the risks of running a vulnerable driver?\n\nWell a vulnerable driver is basically a front door to your house that you cannot lock. If everyone in town is friendly, you're good. But all it takes is one malicious actor to recognize the vulnerable door and waltz right on in.\n\nThe door still functions, and friendly programs like Fan Control are respectful when they have to go in your house through the door.\n\nBut you are less protected while having it installed. I would recommend listening to Defender. If you choose to override Defender, know that your OS's front door is open, and any program you run can use it for whatever they wish.\n\n# Sources\n1) Matt Hand (security researcher), https://medium.com/@matterpreter/cve-2020-14979-local-privilege-escalation-in-evga-precisionx1-cf63c6b95896\n2) CVE Database, https://nvd.nist.gov/vuln/detail/cve-2020-14979\n3) Related Github issue, https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/issues/984\n4) Fan Control Dev, https://www.reddit.com/r/JayzTwoCents/comments/13nwpzq/comment/jldj1o9/\n\nFeel free to ask questions, there's no such thing as a stupid question on my posts.",
    "permalink": "/r/FanControl/comments/1j93doq/why_does_defender_hate_fan_control_an_explanation/",
    "timestamp": "2025-03-11T22:19:12",
    "article_text": null,
    "comments": [
      {
        "score": 4,
        "text": "It's not true that EVGA was anyhow involved in the WinRing0 driver. They were just one of many companies that used it as it was easy to integrate it and open-source. And the driver+signature was accepted by Windows kernel because it used the old (attestation / cross-certified) signing method that was sufficient several years ago and didn't require an expensive EV code-signing certificate. Signing requirements for kernel drivers changed after Win10 release but drivers signed before were still accepted to preserve compatibility. No one had to convince MS to accept that driver, you just bough a certificate for Windows kernel code signing (with MS cross-cert), signed your driver and it worked. The author of WinRing0 had such certificate probably also for other projects he was working on. Today, you need a more expensive EV certificate (issued to businesses only) and need to let MS sign your driver on their portal (validated via customer EV cert).",
        "level": 0
      },
      {
        "score": 1,
        "text": "This is correct, I'll update my post.",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1
    },
    "title": "Authorization Bypass Vulnerability in Vercel Next.js: CVE-2025-29927",
    "text": "It is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware.\n\n*  For Next.js 15.x, this issue is fixed in `15.2.3`\n* For Next.js 14.x, this issue is fixed in `14.2.25`\n* For Next.js versions `11.1.4` thru `13.5.6` we recommend consulting the below workaround.",
    "permalink": "/r/nextjs/comments/1jgsfhf/authorization_bypass_vulnerability_in_vercel/",
    "timestamp": "2025-03-21T21:44:28",
    "article_text": null,
    "comments": [
      {
        "score": 91,
        "text": "lol so like half of nextjs applications are currently sitting vulnerable",
        "level": 0
      },
      {
        "score": 25,
        "text": "The fast way to resolve it: Cloudflare / Vercel or any other CDN / HTTP server (like nginx) firewall rule : Block any request containing this req header: \\`x-middleware-subrequest\\`",
        "level": 1
      },
      {
        "score": 7,
        "text": "Sites deployed on Vercel aren't affected by this exploit",
        "level": 2
      },
      {
        "score": 4,
        "text": "I've got a few and they are not exploitable, so it really depends on your setup. But yeah it's pretty bad.",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1
    },
    "title": "CVE-2025-29927: Authorization Bypass in Next.js Middleware",
    "text": "",
    "permalink": "/r/reactjs/comments/1jhmz1d/cve202529927_authorization_bypass_in_nextjs/",
    "timestamp": "2025-03-23T00:30:08",
    "article_text": null,
    "comments": [
      {
        "score": 47,
        "text": "Reading the details gave me a right chuckle. They decided that the best way to flag to downstream middleware that something already ran was via… http header\n🤦‍♂️",
        "level": 0
      },
      {
        "score": 14,
        "text": "That is genuinely insane",
        "level": 1
      },
      {
        "score": 13,
        "text": "Like having a lock on your door then leaving the key hanging on a hook outside.",
        "level": 1
      },
      {
        "score": 3,
        "text": "Could you elaborate for those uninitiated (a.k.a. me)?",
        "level": 1
      },
      {
        "score": 23,
        "text": "You're a kid, wanting to ask your parents for whatever demand to your heart's content - give me $100, ice cream for dinner, etc.\n\nYou know both parents would say no, but it doesn't matter, since you will just ask Parent 1 and inform them that Parent 2 said it was okay, and that also Parent 1 should not ask Parent 2 about the request.\n\nParent 1 does no validation of what Parent 2 allegedly said, and gives you $100 and ice cream for dinner.",
        "level": 2
      },
      {
        "score": 12,
        "text": "Essentially they hook up a bunch of functions that all align to process a request (middleware).\n\nThey wanted a way to tell if specific function already ran to avoid recursion in case some other function short circuits to a specific one.\n\nRather than define this information in some area outside of user input (e.g. in a property on Request type), they decided to colocate it along with user supplied data aka HTTP headers.\n\nSo all user had to do was send along a request saying ‘already ran authentication’ and next would believe them.",
        "level": 2
      },
      {
        "score": 1,
        "text": "Classic “security through obscurity” type of move lmao",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-23120"
    ],
    "cve_counts": {
      "CVE-2025-23120": 1
    },
    "title": "CVE-2025-23120 - CVSS 9.9 - KB4724",
    "text": "At this time, guidance from Veeam is:\n\n>Note: This vulnerability only impacts domain-joined backup servers, which is against the Security & Compliance Best Practices.\n\nKB: https://www.veeam.com/kb4724\n\nDownload URL: https://download2.veeam.com/VBR/v12/VeeamBackup&Replication_12.3.1.1139_20250315.iso\n\nSHA1: `bb94f8a40ede5f7e55417e018bff603903ad243a`\n\nEdit 1: Looks like there's some other feature improvements under this latest update as well: https://www.veeam.com/kb4696\n\nEdit 2: Updated my Veeam CE install, seems fine so far. There appear to be new versions of the agents for Windows/Linux/Unix too.",
    "permalink": "/r/Veeam/comments/1jf0zia/cve202523120_cvss_99_kb4724/",
    "timestamp": "2025-03-19T16:25:03",
    "article_text": null,
    "comments": [
      {
        "score": 3,
        "text": "The update broke 2 Backups on Azure Local 23H2. You can't update the Transport Service atm. My case already got escalted to R&D",
        "level": 0
      },
      {
        "score": 1,
        "text": "My case got fobbed off with \"disable wdac to install the update\"",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 3,
      "cve-2025-29927": 2
    },
    "title": "CVE-2025-29927: Bypass de auth no Next.js (CRÍTICA)",
    "text": "Pessoal, acabou de ser anunciado uma vulnerabilidade crítica no Nextjs. A vulnerabilidade permite que o invasor autentique no Nextjs sem precisar de credenciais. \n\nO nível de facilidade para executar é absurdo. Literalmente enviar o seguinte header:\n\n    x-middleware-subrequest: middleware\n\npermite acesso, como usuário logado, aos sites que utilizam o middleware do Nextjs para fazer autenticação e autorização.\n\n  \nPelo que entendi, o Nextjs passa o header nos request para identificar loops infinitos e interromper a execução de funções. Neste caso, é possível interromper as funções ligadas a autenticação e acessar o site como usuário logado. Muitas aplicações estão em risco e precisam corrigir a vulnerabilidade.\n\nEssa vulnerabilidade está marcada como **9.1/10 (CRÍTICA) no CVSS**\n\nAqui alguns links para mais informações sobre a vulnerabilidade:\n\n[CVE-2025-29927 | Next.js](https://nextjs.org/blog/cve-2025-29927)\n\n[Critical Next.js Vulnerability: How a Simple Header Bypasses Authentication (CVE-2025-29927) 🕵️ | Neoxs](https://www.neoxs.me/blog/critical-nextjs-middleware-vulnerability-cve-2025-29927-authentication-bypass)",
    "permalink": "/r/brdev/comments/1jiij1p/cve202529927_bypass_de_auth_no_nextjs_crítica/",
    "timestamp": "2025-03-24T04:20:07",
    "article_text": null,
    "comments": [
      {
        "score": 41,
        "text": "https://preview.redd.it/k5sjcl4uwkqe1.jpeg?width=1080&format=pjpg&auto=webp&s=047d3826e055fb03aa4485ffeb592298f8a5b065\n\nLevar em consideração quem pode ser afetado e quem não.",
        "level": 0
      },
      {
        "score": 2,
        "text": "Os únicos que são afetados é quem utiliza o middleware do nextjs para autenticar, aliás não só a autenticação, mas basicamente qualquer tipo de validação feita no middleware está vulnerável.\n\nMuita gente só precisa de um sistema de login simples e não utiliza outros provedores. Então a quantidade de gente afetada é bem alta.",
        "level": 1
      },
      {
        "score": -3,
        "text": "O segundo ponto é o mais importante, não se depende de middleware pra auth",
        "level": 1
      },
      {
        "score": 10,
        "text": "Não tem nada de errado, o middleware é executado em todos os requests. Então por ele você pode validar o cookie, claims e tudo mais antes de processar o request. O problema é que dá para burlar tudo.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1,
      "cve-2025-29927": 1
    },
    "title": "Next.js Middleware Authentication Bypass Vulnerability (CVE-2025-29927) - Simplified With Working Demo 🕵️",
    "text": "I've created a comprehensive yet simple explanation of the critical Next.js middleware vulnerability that affects millions of applications.\n\nThe guide is designed for developers of ALL experience levels - because security shouldn't be gatekept behind complex terminology.\n\n📖 https://neoxs.me/blog/critical-nextjs-middleware-vulnerability-cve-2025-29927-authentication-bypass",
    "permalink": "/r/nextjs/comments/1ji1j4j/nextjs_middleware_authentication_bypass/",
    "timestamp": "2025-03-23T15:15:26",
    "article_text": null,
    "comments": [
      {
        "score": 48,
        "text": "Glad I never used middleware to protect any routes. I protect them directly inside. I check session and redirect if needed.",
        "level": 0
      },
      {
        "score": 9,
        "text": "Yea personally i would prefer moving authentication logic to the backend, and create my proper custom middleware on the client side.",
        "level": 1
      },
      {
        "score": 3,
        "text": "That's where it is at.",
        "level": 2
      },
      {
        "score": 5,
        "text": "do you make some kind of function? otherwise copy pasting the same code is shit",
        "level": 1
      },
      {
        "score": 5,
        "text": "You could make a HoC for your pages.",
        "level": 2
      },
      {
        "score": 2,
        "text": "I do use it, but proxing to wpgrapql endpoint  I check for token auth that its legit.\n\nAnything sensitive its first checked and made sure its allowed in PHP backend..",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-23120"
    ],
    "cve_counts": {
      "CVE-2025-23120": 2
    },
    "title": "Critical Veeam Backup & Replication vulnerability for domain joined backup servers CVE-2025-23120 (KB4724)",
    "text": "https://www.veeam.com/kb4724\n\n\n> **CVE-2025-23120**\n> \n> A vulnerability allowing remote code execution (RCE) by authenticated domain users.\n> \n> Severity: Critical  \n> CVSS v3.1 Score: 9.9  \n> Source: Reported by Piotr Bazydlo of [watchTowr](https://watchtowr.com/)",
    "permalink": "/r/msp/comments/1jf0y3j/critical_veeam_backup_replication_vulnerability/",
    "timestamp": "2025-03-19T16:23:18",
    "article_text": null,
    "comments": [
      {
        "score": 44,
        "text": "Reminder to not domain join your backup servers, or if you do - take extreme caution and ensure it's an independent forest from your other domain(s).",
        "level": 0
      },
      {
        "score": 4,
        "text": "It’s perfectly fine to domain join them, and actually a lot better if you do. However that domain should be a standalone domain that is only used for the backup infrastructure and only has one way trusts to production.",
        "level": 1
      },
      {
        "score": 2,
        "text": "100% this.",
        "level": 1
      },
      {
        "score": 6,
        "text": "I’d say more 75% this because domain joining is the best solution when you have a dedicated backup infrastructure domain and Forrest that uses one way trusts to production.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-27591"
    ],
    "cve_counts": {
      "CVE-2025-27591": 1
    },
    "title": "Below: World Writable Directory in /var/log/below Allows Local Privilege Escalation (CVE-2025-27591)",
    "text": "",
    "permalink": "/r/linux/comments/1jathij/below_world_writable_directory_in_varlogbelow/",
    "timestamp": "2025-03-14T02:20:58",
    "article_text": null,
    "comments": [
      {
        "score": 50,
        "text": "it took me 20 seconds in reading before releasing the program itself was called Below.  I thought it was telling me Below as in \"look below\" :(",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 2
    },
    "title": "Lessons from Next.js Middleware vulnerability CVE-2025-29927: Why Route-Level Auth Checks Are Worth the Extra Work",
    "text": "Hey r/nextjs community,\n\nWith the recent disclosure of CVE-2025-29927 (the Next.js middleware bypass vulnerability), I wanted to share some thoughts on an authentication patterns that I always use in all my projects and that can help keep your apps secure, even in the face of framework-level vulnerabilities like this.\n\nFor those who haven't heard, Vercel recently disclosed a critical vulnerability in Next.js middleware. By adding a special header (`x-middleware-subrequest`) to requests, attackers can completely bypass middleware-based authentication checks. This affects apps that rely on middleware for auth or security checks without additional validation at the route level.\n\nWe can all agree that middleware-based auth is convenient (implement once, protect many routes), this vulnerability highlights why checking auth at the route level provides an additional layer of security. Yes, it's more verbose and requires more code, but it creates a defense-in-depth approach that's resilient to middleware bypasses.\n\nHere's a pattern I've been using, some people always ask why I don't just use the middleware, but that incident proves its effectiveness.   \n  \n**First, create a requireAuth function:**\n\n    export async function requireAuth(Roles: Role[] = []) {\n      const session = await auth();\n    \n      if (!session) {\n        return redirect('/signin');\n      }\n    \n      if (Roles.length && !userHasRoles(session.user, Roles)) {\n        return { authorized: false, session };\n      }\n    \n      return { authorized: true, session };\n    }\n    \n    // Helper function to check roles\n    function userHasRoles(user: Session[\"user\"], roles: Role[]) {\n      const userRoles = user?.roles || [];\n      const userRolesName = userRoles.map((role) => role.role.name);\n      return roles.every((role) => userRolesName.includes(role));\n    }\n\n**Then, implement it in every route that needs protection:**\n\n    export default async function AdminPage() {\n      const { authorized } = await requireAuth([Role.ADMIN]);\n    \n      if (!authorized) return <Unauthorized />;\n    \n      // Your protected page content\n      return (\n        <div>\n          <h1>Admin Dashboard</h1>\n          {/* Rest of your protected content */}\n        </div>\n      );\n    }\n\n# Benefits of This Approach\n\n1. **Resilience to middleware vulnerabilities**: Even if middleware is bypassed, each route still performs its own auth check\n2. **Fine-grained control**: Different routes can require different roles or permissions\n3. **Explicit security**: Makes the security requirements of each route clear in the code\n4. **Early returns**: Auth failures are handled before any sensitive logic executes\n\nI use [Next.js Full-Stack-Kit](https://full-stack-kit.dev) for several projects and it implements this pattern consistently across all protected routes. What I like about that pattern is that auth checks aren't hidden away in some middleware config - they're right there at the top of each page component, making the security requirements explicit and reviewable.\n\nAt first, It might seem tedious to add auth checks to every route (especially when you have dozens of them), this vulnerability shows why that extra work is worth it. Defense in depth is a fundamental security principle, and implementing auth checks at multiple levels can save you from framework-level vulnerabilities.\n\nStay safe guys!",
    "permalink": "/r/nextjs/comments/1jpqw5h/lessons_from_nextjs_middleware_vulnerability/",
    "timestamp": "2025-04-02T15:06:41",
    "article_text": null,
    "comments": [
      {
        "score": 4,
        "text": "Authorisation checks should be done as high and early as reasonable. If it's simple condition like signin status or role and same rule would be applied to whole segment anyway, there's no need to spread it to each child route. Also you'd avoid more expensive RSC execution in case a redirect is necessary.\n\n\nIf the check is more granular e.g. \"....where id=? and foo.owner=?\", 123, user.id)\" then it needs to be done at data access layer obviously. \n\n\nDoing **authentication** in middleware or equivalent concept is another thing. Since it will be done anyway, might as well handle it right away. This would also make standardized auth solutions easier when the whole authentication process could be a preliminary step, establishing the internal user data as result.",
        "level": 0
      },
      {
        "score": 1,
        "text": "Would you then say that authorization should be done at the highest level route that needs to be protected through something like a template.tsx?",
        "level": 1
      },
      {
        "score": 1,
        "text": "What are your thoughts on the potential performance implications of auth checks in middleware? I’m not the sort of dev who typically obsesses much about perf, but this scenario is one exception.\n\nMy understanding (correct me if I’m wrong) is that for a typical app with a partially personalised UI - e.g. a dashboard with the user’s avatar in the top-right - most of the outer app “shell” is static (i.e. the same thing is shown to all users). In this case, it feels wrong to me to dump a blocking auth service check in middleware. Instead, you could conceivably render parts of the screen immediately and then any slower, user-specific elements stream in and replace their skeleton loaders.\n\nAdditionally, you only need to do a single db/auth service hit to verify a user, as this result can then just use React’s cache function to reuse the result across the same server render pass.\n\nOne final pattern I’ve been using is “optimistic” session checks in middleware, which is basically instant as it only checks for a JWT. Of course it’s technically not secure because it could be tampered with, but for rendering basic user data there’s no issue. And for operations that really need full server security, you use row-level security, auth guards in RSCs, server actions, etc. In this way, you get immediate UI rendering with secure data access (it’s just a bit more cumbersome than having a single middleware check).\n\nI think seb markbage supports this pattern from one of his tweets. Also could be a motivating factor for features like partial pre-rendering",
        "level": 1
      },
      {
        "score": 2,
        "text": "Parsing and validating JWT token ( let's say HS256) takes ~5-20 microseconds. Asymmetric ones will be slower but even if it would take 1ms you are completely fine for blocking for 1ms in any typical web application. \n\n\nSessions make much less sense for distributed system but if you're close to db it's perfectly viable. Usually it's just a single index lookup which should be very fast. Again shouldn't be an issue. Most framework default to doing this every request and it isn't an issue.\n\n\nWhy this is an issue with NextJS? Because middleware runs possibly 10000km away from the data. Also people do crazy things like calling an external server ( Supabase for example) to do the auth check which obviously is extremely slow. \n\n\nMy advice? Use JWT and just validate it locally. Extremely fast and simple.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-9956"
    ],
    "cve_counts": {
      "CVE-2024-9956": 1
    },
    "title": "CVE-2024-9956 - PassKey Account Takeover in All Mobile Browsers",
    "text": "",
    "permalink": "/r/cybersecurity/comments/1jhdrha/cve20249956_passkey_account_takeover_in_all/",
    "timestamp": "2025-03-22T17:29:49",
    "article_text": null,
    "comments": [
      {
        "score": 12,
        "text": "What’s everyone’s thoughts on passkeys these days?\n\nThe root cause of this CVE is that the authenticator (your BLE security key) has no built-in mechanism to independently verify the authenticity of the host (domain) it’s communicating with. This absence of “host verification” allows attackers to MITM the BLE-based authentication, redirecting legitimate responses to malicious endpoints.\n\nCool. So your fancy BLE security key basically trusts whoever it connects with over Bluetooth, without ever double-checking who’s on the other end. Oops.\n\nNot an easy fix, but clearly authenticators need a way to explicitly verify the domain before signing responses. Without domain validation PassKeys are vulnerable to subtle but powerful MITM attacks like this one.\n\nAs far as mitigations I can think of a few:\n\nBLE Domain Binding:\n\nEnhance the security of BLE keys by incorporating explicit domain checks directly into the BLE handshake. This would ensure that the authenticator independently verifies the host’s identity, preventing unauthorized access from third-party devices.\n\nOut-of-Band Domain Checks:\n\nImplement a secondary, trusted channel (such as NFC or a “tap-to-confirm” feature on the security device) to validate the domain requesting PassKey credentials. This would provide an additional layer of verification before the device trusts the request without hesitation.\n\nChallenge-Based Verification:\n\nHave the authenticator issue a cryptographic challenge specifically tied to the domain. The authenticator won’t finalize the authentication unless the host proves its legitimacy cryptographically. In other words, make the domain prove it’s not an imposter first.",
        "level": 0
      },
      {
        "score": -19,
        "text": "It’s a new technology that hasn’t been battle tested. Adopt if you wanna beta test for free.\n\nPersonally, this is just device authentication cookies dressed in their Sunday best. \n\nI’m not a fan and will continue to ignore prompts to use them.",
        "level": 1
      },
      {
        "score": 23,
        "text": "To me they seem to basically give everyone a yubikey. Which we've seen as being superior to token 2FA. I think Passkeys a great. Much harder to Phish.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1,
      "cve-2025-29927": 1
    },
    "title": "🚨 Next.js Middleware Authentication Bypass (CVE-2025-29927) explained for all developers!",
    "text": "I've broken down this new critical security vulnerability into simple steps anyone can understand.\n\nOne HTTP header = complete authentication bypass!\n\nPlease take a look and let me know what are your thoughts 💭 \n\n📖 https://neoxs.me/blog/critical-nextjs-middleware-vulnerability-cve-2025-29927-authentication-bypass",
    "permalink": "/r/webdev/comments/1ji1wmv/nextjs_middleware_authentication_bypass/",
    "timestamp": "2025-03-23T15:32:25",
    "article_text": null,
    "comments": [
      {
        "score": 11,
        "text": "Why not link the CVE in your article?",
        "level": 0
      },
      {
        "score": -10,
        "text": "Hey there 😃\n\nYes it’s there and i also added a dedicated section at the end for references i included the original security researcher who found this vulnerability (they did an amazing work and deserve the support) and also the official nextjs announcement regarding this vulnerability.",
        "level": 1
      },
      {
        "score": 1,
        "text": "Why so much down votes haha 😅",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-30401"
    ],
    "cve_counts": {
      "CVE-2025-30401": 1
    },
    "title": "WhatsApp vulnerability could be used to infect Windows users with malware (CVE-2025-30401)",
    "text": "",
    "permalink": "/r/cybersecurity/comments/1jv57l7/whatsapp_vulnerability_could_be_used_to_infect/",
    "timestamp": "2025-04-09T13:01:22",
    "article_text": null,
    "comments": [
      {
        "score": -6,
        "text": "[removed]",
        "level": 0
      },
      {
        "score": 27,
        "text": "🤖🚀 I just loooove reading AI Slop, please give me more of those lazy, uninspired mundane ad comments.  🤖🚀",
        "level": 1
      },
      {
        "score": 20,
        "text": "OP was banned for this comment.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-12425",
      "CVE-2024-12426"
    ],
    "cve_counts": {
      "CVE-2024-12425": 1,
      "CVE-2024-12426": 1
    },
    "title": "Exploiting LibreOffice (CVE-2024-12425 and CVE-2024-12426)",
    "text": "",
    "permalink": "/r/hacking/comments/1jgcghl/exploiting_libreoffice_cve202412425_and/",
    "timestamp": "2025-03-21T08:59:17",
    "article_text": null,
    "comments": [
      {
        "score": 12,
        "text": "LibreOffice is a great FOSS suite for writing and awesome alternative for MS Office but honestly, I feel like it's bound to have these vulns :( it's so unfortunate",
        "level": 0
      },
      {
        "score": 9,
        "text": "To be fair, office has had similar vulns as well for it's entire existence XD\n\nTfw scripting features run scripts.\n\nAll the more reason to never use a spreadsheet or word processor as a database/web service",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-0117",
      "CVE-2025-0114",
      "CVE-2025-0116",
      "CVE-2025-0115",
      "CVE-2025-0118"
    ],
    "cve_counts": {
      "CVE-2025-0114": 2,
      "CVE-2025-0115": 2,
      "CVE-2025-0116": 2,
      "CVE-2025-0117": 2,
      "CVE-2025-0118": 2
    },
    "title": "Attention - CVE",
    "text": "Hi, \n\nThat might be important for one or the other of you! :)\n\n \nPrisma Access Browser\n\nPAN-SA-2025-0007 Chromium: Monthly Vulnerability Update (March 2025) (Severity: HIGH)\nhttps://security.paloaltonetworks.com/PAN-SA-2025-0007\n \n \nPAN-OS\n\nCVE-2025-0114 PAN-OS: Denial of Service (DoS) in GlobalProtect (Severity: MEDIUM)\nhttps://security.paloaltonetworks.com/CVE-2025-0114\n \nCVE-2025-0115 PAN-OS: Authenticated Admin File Read Vulnerability in PAN-OS CLI (Severity: MEDIUM)\nhttps://security.paloaltonetworks.com/CVE-2025-0115\n \nCVE-2025-0116 PAN-OS: Firewall Denial of Service (DoS) Using a Specially Crafted LLDP Frame (Severity: MEDIUM)\nhttps://security.paloaltonetworks.com/CVE-2025-0116\n \n \nGlobalProtect App\n\nCVE-2025-0117 GlobalProtect App: Local Privilege Escalation (PE) Vulnerability (Severity: MEDIUM)\nhttps://security.paloaltonetworks.com/CVE-2025-0117\n \nCVE-2025-0118 GlobalProtect App: Execution of Unsafe ActiveX Control Vulnerability (Severity: LOW)\nhttps://security.paloaltonetworks.com/CVE-2025-0118\n \n \n",
    "permalink": "/r/paloaltonetworks/comments/1j9twx6/attention_cve/",
    "timestamp": "2025-03-12T20:24:23",
    "article_text": null,
    "comments": [
      {
        "score": 24,
        "text": "Pretty meh, started getting used to the 9+ CVEs already\n\nStep up your CVE game PA.",
        "level": 0
      },
      {
        "score": 6,
        "text": "These aren't even all that bad.",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-23120"
    ],
    "cve_counts": {
      "CVE-2025-23120": 1,
      "cve-2025-23120": 2
    },
    "title": "Veeam CVE 9.9 Alert -",
    "text": "**// Overview**\n\nOn March 19th, 2025, software vendor Veeam announced a patch to address **CVE-2025-23120,** which allows for remote code execution (RCE) by any domain authenticated users. The CVSS score is 9.9 representing a serious risk, however this impacts only AD Domain-joined backup servers.\n\nThe attack takes advantage of a deserialization vulnerability in two different .NET classes. Deserialization is a process to reassemble data after it has been broken into smaller pieces in a stream of bytes known as serialization. The vendor, watchTowr, who reported the vulnerability to Veeam, made note to mention the process of relying on deny-lists, instead of accept-lists is one of the root causes, as it allows attackers to attempt to identify other classes which are not blocked to facilitate code execution.\n\nAs Sophos has previously reported\\[1\\], Veeam backup servers are frequently targeted by financially motivated threat actors to encrypt and ransom an organization’s data. We recommend high priority be given to patching your backup servers if they meet the criteria below. In addition, Sophos does support Veeam integration to further strengthen your protections\\[2\\].\n\n**// What you should do**\n\nCustomers running Veeam Backup & Replication software products are advised to upgrade to version 12.3.1, or apply the latest hotfix 12.3 following the vendor’s specific guidance:\n\n1. 12.3.0.310 and all earlier builds of version 12 are impacted\n\nPlease be advised that application of this hotfix may overwrite previous hotfixes per Veeam’s guidance.\n\n  \n[https://www.veeam.com/kb4724](https://nam11.safelinks.protection.outlook.com/?url=https%3A%2F%2Fvd5djq9e.r.us-west-2.awstrack.me%2FL0%2Fhttps%3A%252F%252Fwww.veeam.com%252Fkb4724%2F1%2F01010195ba6e1dc2-bee103a9-f191-4ba1-a15f-643badbd5c97-000000%2FcE1OH5jf1aN1IMb1iHbmpRTfxSU%3D419&data=05%7C02%7Cjasoncohenour%40ovfcu.com%7Cdaf7a7bdfae64826d3ff08dd68b865f0%7Cf5ea2130c88948fa8b41bbb81c80157e%7C0%7C0%7C638781863399659476%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=K0kuV3JbE1IPQIegL3zU0vPOVGrB0Sv6Z6Cap0bh0Ko%3D&reserved=0)\n\nAdditional Reporting\n\n1. [https://labs.watchtowr.com/by-executive-order-we-are-banning-blacklists-domain-level-rce-in-veeam-backup-replication-cve-2025-23120/](https://nam11.safelinks.protection.outlook.com/?url=https%3A%2F%2Fvd5djq9e.r.us-west-2.awstrack.me%2FL0%2Fhttps%3A%252F%252Flabs.watchtowr.com%252Fby-executive-order-we-are-banning-blacklists-domain-level-rce-in-veeam-backup-replication-cve-2025-23120%252F%2F1%2F01010195ba6e1dc2-bee103a9-f191-4ba1-a15f-643badbd5c97-000000%2Fdb6vxeGtQee5ft54t3pL5rUDfo8%3D419&data=05%7C02%7Cjasoncohenour%40ovfcu.com%7Cdaf7a7bdfae64826d3ff08dd68b865f0%7Cf5ea2130c88948fa8b41bbb81c80157e%7C0%7C0%7C638781863399678778%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=kEMKhOLBXIiSXvlyqieJ3XmmtfZkJ7nnuVK%2FF3iYKfI%3D&reserved=0)\n2. \\[1\\] [https://news.sophos.com/en-us/2024/11/08/veeam-exploit-seen-used-again-with-a-new-ransomware-frag/](https://nam11.safelinks.protection.outlook.com/?url=https%3A%2F%2Fvd5djq9e.r.us-west-2.awstrack.me%2FL0%2Fhttps%3A%252F%252Fnews.sophos.com%252Fen-us%252F2024%252F11%252F08%252Fveeam-exploit-seen-used-again-with-a-new-ransomware-frag%252F%2F1%2F01010195ba6e1dc2-bee103a9-f191-4ba1-a15f-643badbd5c97-000000%2F2Bz90ljGw9uqvG4GEExuhoDd9bM%3D419&data=05%7C02%7Cjasoncohenour%40ovfcu.com%7Cdaf7a7bdfae64826d3ff08dd68b865f0%7Cf5ea2130c88948fa8b41bbb81c80157e%7C0%7C0%7C638781863399694184%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=fBJv4pYTeO2KG0FHMF9S2TzFix4a636Xb86hT9q7FRc%3D&reserved=0)\n\n",
    "permalink": "/r/sysadmin/comments/1jgrpld/veeam_cve_99_alert/",
    "timestamp": "2025-03-21T21:12:33",
    "article_text": null,
    "comments": [
      {
        "score": 6,
        "text": "You're late to the party: https://old.reddit.com/r/sysadmin/search?q=CVE-2025-23120&restrict_sr=on",
        "level": 0
      },
      {
        "score": 4,
        "text": "Late?  This is like showing up the Thursday after the Saturday party with a vegetable tray and Busch lite.",
        "level": 1
      },
      {
        "score": 3,
        "text": "That's just early for the next party.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-26506"
    ],
    "cve_counts": {
      "CVE-2025-26506": 1
    },
    "title": "HP Warns of Critical Security Flaw in LaserJet Printers - CVE-2025-26506 (CVSSv4 9.2)",
    "text": "",
    "permalink": "/r/cybersecurity/comments/1jb4br2/hp_warns_of_critical_security_flaw_in_laserjet/",
    "timestamp": "2025-03-14T13:48:47",
    "article_text": null,
    "comments": [
      {
        "score": 16,
        "text": "Less cancer:\n\nhttps://nvd.nist.gov/vuln/detail/CVE-2025-26506\n\nAttackerKB - hasn’t updated as of yet:    \n\nhttps://attackerkb.com/topics/l1wN22ZLnI/cve-2025-26506?referrer=search",
        "level": 0
      },
      {
        "score": 3,
        "text": "Thank you",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 1
    },
    "title": "Is The Sofistication In The Room With Us? - X-Forwarded-For and Ivanti Connect Secure (CVE-2025-22457) - watchTowr Labs",
    "text": "",
    "permalink": "/r/netsec/comments/1jrcdex/is_the_sofistication_in_the_room_with_us/",
    "timestamp": "2025-04-04T13:50:55",
    "article_text": null,
    "comments": [
      {
        "score": 10,
        "text": "It seems like they literally said \"well the exploit string is limited to a small set of characters, so it's hard to exploit\" without checking if it would be trivial for an attacker to just...only use that small set of characters. It could have been limited to a single character and it wouldn't have mattered in the slightest.",
        "level": 0
      },
      {
        "score": 2,
        "text": "I'm pretty sure if I go digging in my Tools folder I have a tool for exactly this sort of situation.  I'm sure I could search one up in five minutes if not.  They ship that stock with Kali Linux.\n\nWhat a bizarre idea.\n\nEdit: On reading more closely, it's only numbers and period characters, so that's relatively constrained, but yeah... thinking this couldn't be used to devastating effect is ridiculous.",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-27564"
    ],
    "cve_counts": {
      "CVE-2024-27564": 1
    },
    "title": "Hackers Exploit ChatGPT with CVE-2024-27564, 10,000+ Attacks in a Week",
    "text": "",
    "permalink": "/r/InfoSecNews/comments/1jdokdk/hackers_exploit_chatgpt_with_cve202427564_10000/",
    "timestamp": "2025-03-17T21:36:37",
    "article_text": null,
    "comments": [
      {
        "score": 7,
        "text": "Their being really misleading in stating this is an OpenAI hack...\n\nThis is a hack in a ChatGPT wrapper application written in PHP unrelated to OpenAI.\n\n[https://github.com/dirk1983/chatgpt](https://github.com/dirk1983/chatgpt)\n\nIt has nothing to do with OpenAI, heavy click bait going on here. This post title included.\n\nThis is a story as old as the internet, some dude puts an example/demo file in his repo library that basically is `<?php exec($_GET['parameter']); ?>` and everyone who just git clones the repo leaves it laying around for someone else to find using Google.",
        "level": 0
      },
      {
        "score": -6,
        "text": "Who said it's an OpenAI hack? It exactly states that a vulnerability (CVE-2024-27564) is being exploited. The company who revealed these attacks is Veriti AI. The clearly state that \"Attackers are actively targeting OpenAI, exploiting CVE-2024-27564, a Server-Side Request Forgery (SSRF) vulnerability in OpenAI’s ChatGPT infrastructure.\" \n\nIf this is not accurate you should contact Veriti and prove them wrong. I am sure if this was inaccurate OpenAI would have argued it to Veriti before the report had gone live.",
        "level": 1
      },
      {
        "score": 7,
        "text": "**From the post title:**  \n*\"Hackers exploit ChatGPT\"...*\n\n**To the article:**  \n*(Deeba Ahmed wrote)*  \n*\"exploitation of a vulnerability within OpenAI’s ChatGPT infrastructure\"...*\n\nBoth of these statements are false and pure clickbait.\n\nIf you actually check the **CVE**, you'll see it doesn't mention OpenAI at all. Instead, it points directly to the **GitHub repository** I previously called out:\n\n* **Actual CVE:** [CVE-2024-27564](https://nvd.nist.gov/vuln/detail/CVE-2024-27564)\n* **Vulnerable Software:** [GitHub Repository](https://github.com/dirk1983/chatgpt) (NOT OpenAI)\n\n[Veriti.ai](http://Veriti.ai) is completely off the mark. Their entire article wrongly frames this as an OpenAI hack, when in reality, it's unrelated to OpenAI entirely:  \n[Veriti.ai's article](https://veriti.ai/blog/cve-2024-27564-actively-exploited/)\n\nConsidering [Veriti.ai](https://veriti.ai/odin-ai-cybersearch/) sells software that competes with OpenAI's offerings, I'd take their claims with a hefty grain of salt.\n\nHonestly, I wouldn’t be surprised if an AI wrote that sloppy article. Considering the ONLY mention of ChatGPT in ANY of this, is the Github Repository name owned by one: [dirk1983](https://github.com/dirk1983/) (Not OpenAI)\n\nI'll let an AI explain it better: [ChatGPT Analysis](https://chatgpt.com/share/67d8b6e7-9e9c-800c-a6ab-b886c0c258af)",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1
    },
    "title": "Detect NetxJS CVE-2025-29927 efficiently and at scale",
    "text": "",
    "permalink": "/r/netsec/comments/1jlqota/detect_netxjs_cve202529927_efficiently_and_at/",
    "timestamp": "2025-03-28T08:55:16",
    "article_text": null,
    "comments": [
      {
        "score": 6,
        "text": "I dont see the tree sitter library being shared in the article. Whats the point of writing detecting these bugs at scale when the authors cant share the details that can lead someone scanning at scale.",
        "level": 0
      },
      {
        "score": 2,
        "text": "You mean this very well known library : https://tree-sitter.github.io/tree-sitter/#parsers\nI might be misinterpreting you.",
        "level": 1
      },
      {
        "score": 2,
        "text": "I think they're referring to the tool mentioned in the post (which was built using the tree-sitter library) that analyzes JS code to retrieve hidden paths that normally wouldn't be returned when crawling the app.\n\n> **For this technique, we have developed a tool** that uses TreeSitter with custom queries and a custom variable resolution mechanism to be as precise as we could given the complexity of the minified JavaScript content we analyze.\n\n...\n\n> So, finally, using our understanding on the vulnerability and the way to find entry points, we simply automate it for each potentially vulnerable application:\n\n> - Fetch all .js files loaded by the application\n\n> - **Analyze them to find entrypoints using our JS analyzer tool**\n\n> - Run the detection template on these entrypoints",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29824"
    ],
    "cve_counts": {
      "CVE-2025-29824": 1
    },
    "title": "CVE-2025-29824 Information",
    "text": "Just checking in with everyone to see if they have found any additional information involving this CVE with CrowdStrike? I have only found their standard blog information about patch Tuesday but nothing else. ",
    "permalink": "/r/crowdstrike/comments/1jv6wfr/cve202529824_information/",
    "timestamp": "2025-04-09T14:18:09",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "Hi there. *Fortunately* (?), CLFS is used and abused so Falcon has a ton of detection content that looks for that behavior. MSFT has some fairly (read: very) [broad](https://www.microsoft.com/en-us/security/blog/2025/04/08/exploitation-of-clfs-zero-day-leads-to-ransomware-activity/) hunting rules on their site looking for post-exploitation behavior of CLFS exploitation and rasomware execution.\n\nI'll translate them in case they are useful to you:\n\n**Detect CLFS BLF file creation after exploitation of CVE 2025-29824**\n\n    #event_simpleName=/FileWritten$/F FileName=/\\.blf/iF FilePath=/\\\\ProgramData\\\\SkyPDF\\\\/iF\n\n**LSSASS process dumping activity**\n\nFalcon will throw an absolute fit if this happens. No need to search for it. Falcon is going to bring it straight to you.\n\n**Ransomware Process Activity**\n\n    #event_simpleName=ProcessRollup2 CommandLine=/(?<marker>(dllhost|bcdedit|wbadmin|wevtutil))/iF\n    | marker:=lower(\"marker\")\n    | case {\n        marker=dllhost | CommandLine=/\\\\Windows\\\\system32\\\\dllhost.exe\\s+--do/iF;\n        marker=bcdedit | CommandLine=/recoveryenabled\\s+no/iF;\n        marker=wbadmin | CommandLine=/delete\\s+catalog\\s+-quiet/iF;\n        marker=wevtutil| CommandLine=/cl\\s+Application/iF;\n    }\n\n**PipeMagic and RansomEXX fansomware domains**\n\n    #event_simpleName=DnsRequest\n    | in(field=\"DomainName\", values=[\"*aaaaabbbbbbb.eastus.cloudapp.azure.com\",\"*jbdg4buq6jd7ed3rd6cynqtq5abttuekjnxqrqyvk4xam5i7ld33jvqd.onion\",\"*uyhi3ypdkfeymyf5v35pbk3pz7st3zamsbjzf47jiqbcm3zmikpwf3qd.onion\"])\n\n**Disclaimer**\n\nThese searches, which I did not come up with, are pretty broad and mostly target post-infection LOL activity. You may see these in your environment. That does not mean exploitation of CVE 2025-29824 has occurred. They are points of investigation :)\n\nCheers.",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-36347"
    ],
    "cve_counts": {
      "CVE-2024-36347": 1
    },
    "title": "Update AMD AGESA V2 1.2.0.E for fix AMD CPU microcode signature verification vulnerability (CVE-2024-36347)",
    "text": "When we can expect AMD AGESA V2 1.2.0.E agesa for am4 socket?\n\nGigabyte and asus released them already.",
    "permalink": "/r/MSI_Gaming/comments/1jq0dxj/update_amd_agesa_v2_120e_for_fix_amd_cpu/",
    "timestamp": "2025-04-02T21:28:28",
    "article_text": null,
    "comments": [
      {
        "score": 3,
        "text": "Waiting for update.",
        "level": 0
      },
      {
        "score": 2,
        "text": "Once you qualify for Social Security, stop waiting ... :P \n\nThis is MSI we're talking about ...",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-24514",
      "CVE-2025-1097",
      "CVE-2025-1974",
      "CVE-2025-1098"
    ],
    "cve_counts": {
      "CVE-2025-1097": 2,
      "CVE-2025-1098": 2,
      "CVE-2025-24514": 2,
      "CVE-2025-1974": 2
    },
    "title": "Critical IngressNightmare RCE vulnerabilities (CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974) in Ingress NGINX Controller",
    "text": "Link to blogpost: [https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities)  \n  \nWiz Research just disclosed a new set of unauthenticated Remote Code Execution (RCE) vulnerabilities in Ingress NGINX Controller for Kubernetes (nicknamed **IngressNightmare**). These are serious — with a CVSS v3.1 base score of **9.8**, and they allow an attacker to execute arbitrary code in the cluster’s Ingress NGINX Controller pod and potentially access *all secrets across all namespaces*. If you’re running Kubernetes in production, please read on.\n\n**TL;DR**\n\n* **Vulnerabilities:** CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974\n* **Severity:** Critical (9.8 CVSS v3.1)\n* **Potential Impact:** Full cluster takeover (access to all secrets in the cluster).\n* **Affected Component:** Admission controller inside Ingress NGINX (a very commonly used ingress controller).\n\n**Summary**  \nIngress NGINX Controller is massively popular. Wiz says they’ve found **over 6,500** publicly exposed clusters – including some at Fortune 500 companies – that have the admission controller wide open to the internet, making them critical targets.\n\nIngress NGINX by default deploys a validating webhook (admission controller) that checks incoming ingress objects for compliance. But in these vulnerable versions, that webhook can be abused to inject malicious NGINX configs. That eventually leads to RCE within the Ingress NGINX pod. Combine that with the admission controller’s elevated privileges, and it’s game over.\n\n**Affected Versions / Fix**\n\n* **Fixed in:** Ingress NGINX Controller versions `1.12.1` and `1.11.5`.\n* If you’re running an older release, you’re at risk. Patch ASAP.\n\n**Mitigation Steps**\n\n1. **Update** to the latest Ingress NGINX Controller (1.12.1+ or 1.11.5+).\n2. **Lock down the admission webhook** so it’s only reachable by the Kubernetes API Server.\n   * This means restricting network policies or ensuring the webhook isn’t publicly exposed.\n3. **If you can’t patch**, you can:\n   * Temporarily **disable** the validating webhook by removing the `ingress-nginx-admission` ValidatingWebhookConfiguration and the `--validating-webhook` argument. (But remember: re-enable it once you upgrade, because it does serve useful security checks!)\n   * Apply **strict network policies** so only the K8s control plane can talk to this webhook.",
    "permalink": "/r/sysadmin/comments/1jjjhjm/critical_ingressnightmare_rce_vulnerabilities/",
    "timestamp": "2025-03-25T13:34:59",
    "article_text": null,
    "comments": [
      {
        "score": 11,
        "text": "Sometimes you're just happy, you don't use all of that fancy stuff.",
        "level": 0
      },
      {
        "score": 4,
        "text": "LOL, this makes me happy I don't use Nginx, but now I worry about Traefik and what might be found there. However, I also don't use Kubernetes (yet), so maybe a bit less risk there?",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-23120"
    ],
    "cve_counts": {
      "CVE-2025-23120": 1
    },
    "title": "By Executive Order, We Are Banning Blacklists - Domain-Level RCE in Veeam Backup & Replication (CVE-2025-23120) - watchTowr Labs",
    "text": "",
    "permalink": "/r/netsec/comments/1jff8u9/by_executive_order_we_are_banning_blacklists/",
    "timestamp": "2025-03-20T02:54:12",
    "article_text": null,
    "comments": [
      {
        "score": 18,
        "text": "This is not an executive order from Trump.  This is a report of a vulnerability in Veeam’s blacklist functionality which is used against certain objects in code.  This is a rough summary.\n\nThere is nothing in the article saying this bug was put in intentionally by law or executive order by the US federal government.",
        "level": 0
      },
      {
        "score": 28,
        "text": "watchTowr meme a lot, their title is not intended to be serious",
        "level": 1
      },
      {
        "score": 17,
        "text": "I’m sorry.  I’ve been on-edge when it comes to hearing “executive order” as my response is always “what institution is getting destroyed now?”",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-1974"
    ],
    "cve_counts": {
      "CVE-2025-1974": 1
    },
    "title": "Ingress-nginx CVE-2025-1974: What It Is and How to Fix It",
    "text": "",
    "permalink": "/r/kubernetes/comments/1jjf2mu/ingressnginx_cve20251974_what_it_is_and_how_to/",
    "timestamp": "2025-03-25T09:03:31",
    "article_text": null,
    "comments": [
      {
        "score": 10,
        "text": "To save time to the readers, if you used helm, just helm repo update then helm upgrade.",
        "level": 0
      },
      {
        "score": 10,
        "text": "So like any other security update with no breaking changes? 😁\n\nWhy is everything a news article/tutorial nowadays? Content farming?",
        "level": 1
      },
      {
        "score": 5,
        "text": "Security first before functionality? Lezdo it 🤣",
        "level": 2
      },
      {
        "score": 2,
        "text": "Last time I checked the new version has regressions. Easier to disable the admission webhooks",
        "level": 1
      },
      {
        "score": 2,
        "text": "Actually, there are 4 CVEs reported and only one CVE will be resolved by disabling the admission webhook. The other 3, can only be mitigated by updating.",
        "level": 2
      },
      {
        "score": 2,
        "text": "Make sure using —reuse-values. My ingress allows snippet and I forgot to use it. Ended up getting 404 and had to edit configmap to add:\n  annotations-risk-level: Critical",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-0123"
    ],
    "cve_counts": {
      "CVE-2025-0123": 1
    },
    "title": "CVE-2025-0123 PAN-OS",
    "text": "This CVE just came out about a vulnerability in HTTP/2 Packet Captures\n\nIt looks like this CVE can be fixed by just turning off HTTP2? Am I reading that correctly?",
    "permalink": "/r/paloaltonetworks/comments/1jvcn0f/cve20250123_panos/",
    "timestamp": "2025-04-09T18:13:44",
    "article_text": null,
    "comments": [
      {
        "score": 2,
        "text": "Be careful with disabling http/2 when using AppID in firewall rules. It might happen that some web apps can’t get identified properly ending with blocking them",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2017-5715",
      "CVE-2017-5753"
    ],
    "cve_counts": {
      "CVE-2017-5715": 2,
      "CVE-2017-5753": 2
    },
    "title": "Microsoft CVE-2017-5715 & CVE-2017-5753 'Spectre'",
    "text": "We have Rapid7 in our environment and one of the vulnerabilities that I've been chasing down is both CVEs\n\nCVE-2017-5715  \nCVE-2017-5753\n\nThe vulnerability proof is HKEY\\_LOCAL\\_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Memory Management. There is s FeatureSettingsOverride that does not exist. I've checked other systems that have the same OS versions, and they also do not have a FeatureSettingsOverride entry either.\n\nI thought it would be as simple as a KB install, but it seems a bit more complex than that. I've tried adding the registry value manually on a few systems and rerunning Rapid7 report, but they keep coming back as still vulnerable.\n\nI'm assuming someone out there has mitigated this before and knows an automated approach. Any advice will be greatly appreciated!",
    "permalink": "/r/sysadmin/comments/1jalxun/microsoft_cve20175715_cve20175753_spectre/",
    "timestamp": "2025-03-13T20:31:28",
    "article_text": null,
    "comments": [
      {
        "score": 10,
        "text": "For me, this vulnerability was in CVE-2022-0001 but it's the same fix I believe.  \nThere seems to be 2 ways to fix this, either adding that key with this value:\n\nreg add \"HKEY\\_LOCAL\\_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Memory Management\" /v FeatureSettingsOverride /t REG\\_DWORD /d 0x00800000 /f\n\nBut, there is also a \"Combined Mitigation\" that can be used with this key:  \n  \nreg add \"HKEY\\_LOCAL\\_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Memory Management\" /v FeatureSettingsOverride /t REG\\_DWORD /d 0x00802048 /f\n\nWe remediated through Crowdstrike and that's where I saw the combined mitigation is the one it wanted for some of them. Seems to be whether you have Hyper V enabled or not that the key differs.  \nGood luck, hope this helped",
        "level": 0
      },
      {
        "score": 3,
        "text": "I also used the crowdstrike mitigation recommendations. One point I’d clarify. It’s not hyper-v but hyper threading enabled.",
        "level": 1
      },
      {
        "score": 2,
        "text": "Ah thank you! I remembered reading about Hyper something. I should have looked it up, but only kept the keys in my notes. Thank you for the correction!",
        "level": 2
      },
      {
        "score": 2,
        "text": "Are the registry entries needed on literally all CPUs?",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-25291",
      "CVE-2025-25292"
    ],
    "cve_counts": {
      "CVE-2025-25291": 1,
      "CVE-2025-25292": 1
    },
    "title": "Fixes for new critical authentication bypasses affecting ruby-saml and omniauth-saml were published (CVE-2025-25291 + CVE-2025-25292), update!",
    "text": "",
    "permalink": "/r/ruby/comments/1ja6lh0/fixes_for_new_critical_authentication_bypasses/",
    "timestamp": "2025-03-13T07:32:40",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "Perhaps consider xmldsig library…",
        "level": 0
      },
      {
        "score": 1,
        "text": "It does not cover encryption and its no maintained (last commit 3y ago).  \nThe last vulnerabilitis discovered in ruby-saml are not directly related to how xmldsig was implemented, but how was used.",
        "level": 1
      },
      {
        "score": 1,
        "text": "There is an xmlenc library as well for that. It’s all used in libsaml gem",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-0120"
    ],
    "cve_counts": {
      "CVE-2025-0120": 1
    },
    "title": "CVE-2025-0120",
    "text": "This is for the GlobalProtect App: Local Privilege Escalation \n\nI’m currently on 6.2.6, the unaffected version is 6.2.7-h3 or 6.2.8, but I do not see it when I go to Device -> GlobalProtect Client. Am I the only one with this issue? ",
    "permalink": "/r/paloaltonetworks/comments/1jvchyq/cve20250120/",
    "timestamp": "2025-04-09T18:08:08",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "6.2.8 seems to be there for me on a 445 , 6.2.7-h3 isn't (unless im using the wrong command) \n\nDone in cli \n\nrequest global-protect-client software download version 6.2.8",
        "level": 0
      },
      {
        "score": 1,
        "text": "Yup i see 6.2.8. Not 6.2.7-h3",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-1974"
    ],
    "cve_counts": {
      "CVE-2025-1974": 1,
      "cve-2025-1974": 1
    },
    "title": "Ingress-nginx CVE-2025-1974",
    "text": "This CVE (https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/) is also affecting rancher, right?\n\nLatest image for the backend (https://hub.docker.com/r/rancher/mirrored-nginx-ingress-controller-defaultbackend/tags) seems to be from 4 months ago.\n\nI could not find any rancher-specific news regarding this CVE online.\n\nAny ideas?",
    "permalink": "/r/rancher/comments/1jjewem/ingressnginx_cve20251974/",
    "timestamp": "2025-03-25T08:50:00",
    "article_text": null,
    "comments": [
      {
        "score": 6,
        "text": "The Rancher team posted about this [here](https://www.suse.com/support/kb/doc/?id=000021756) and an [rke2 issue](https://github.com/rancher/rke2/issues/7953) has a bit more detail and progress.",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-27591"
    ],
    "cve_counts": {
      "CVE-2025-27591": 1
    },
    "title": "Below: World Writable Directory in /var/log/below Allows Local Privilege Escalation (CVE-2025-27591)",
    "text": "",
    "permalink": "/r/rust/comments/1jatht8/below_world_writable_directory_in_varlogbelow/",
    "timestamp": "2025-03-14T02:21:24",
    "article_text": null,
    "comments": [
      {
        "score": -2,
        "text": "An example of how you still need to be careful of security bugs, even in Rust.",
        "level": 0
      },
      {
        "score": 10,
        "text": "Yes ofc. Rust is not a silver bullet solution for every bug out there, neither it claimed to be.\n\nWe can still make logical bugs and other bugs in it.",
        "level": 1
      },
      {
        "score": 6,
        "text": "There is no room to even take Rust into consideration, this CVE has absolutely nothing to do with the language. Security bugs are not memory safety issues.\n\nWhy'd you re-post this here?",
        "level": 1
      },
      {
        "score": 5,
        "text": "Below is apparently written in Rust.\n\nA little reminder that Rust doesn't prevent security bugs, only memory safety bugs, may not be a bad idea.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-24813"
    ],
    "cve_counts": {
      "CVE-2025-24813": 2
    },
    "title": "Unifi Network Server and Tomcat CVE-2025-24813",
    "text": "It seems like UNS uses Tomcat under the hood - is there any exposure due to CVE-2025-24813?",
    "permalink": "/r/Ubiquiti/comments/1jeetg7/unifi_network_server_and_tomcat_cve202524813/",
    "timestamp": "2025-03-18T20:20:14",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "Hello!  Thanks for posting on r/Ubiquiti!\n\nThis subreddit is here to provide unofficial technical support to people who use or want to dive into the world of Ubiquiti products.  If you haven’t already been descriptive in your post, please take the time to edit it and add as many useful details as you can.\n\nUbiquiti makes a great tool to help with figuring out where to place your access points and other network design questions located at:\n\nhttps://design.ui.com\n\nIf you see people spreading misinformation or violating the \"don't be an asshole\" general rule, please report it!\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/Ubiquiti) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 1
    },
    "title": "Suspected China-Nexus Threat Actor Actively Exploiting Critical Ivanti Connect Secure Vulnerability (CVE-2025-22457)",
    "text": "",
    "permalink": "/r/netsec/comments/1jqoobu/suspected_chinanexus_threat_actor_actively/",
    "timestamp": "2025-04-03T17:33:02",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-8690"
    ],
    "cve_counts": {
      "CVE-2024-8690": 1
    },
    "title": "Palo Alto Cortex XDR bypass (CVE-2024-8690)",
    "text": "",
    "permalink": "/r/netsec/comments/1jgra20/palo_alto_cortex_xdr_bypass_cve20248690/",
    "timestamp": "2025-03-21T20:54:12",
    "article_text": null,
    "comments": [
      {
        "score": 0,
        "text": "Two things:\n\n1. Palo alto [states](https://security.paloaltonetworks.com/CVE-2024-8690) that different versions were affected - 8.2 and up was not affected. \n\n2. I‘m curious why their Windows ELAM component didn‘t catch this. I thought it was designed against this exact threat?",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-2825",
      "CVE-2025-31161"
    ],
    "cve_counts": {
      "CVE-2025-31161": 10,
      "cve-2025-31161": 2,
      "cve-2025-2825": 2
    },
    "title": "Critical Vulnerability: CrushFTP CVE-2025-31161 Auth Bypass and Post-Exploitation",
    "text": "**TL;DR:** CVE-2025-31161 is a critical severity vulnerability allowing attackers to control how user authentication is handled by CrushFTP managed file transfer (MFT) software. **We strongly recommend patching immediately to avoid affected versions 10.0.0 through 10.8.3 and 11.0.0 through 11.3.0.** Successful exploitation of CVE-2025-31161 would give attackers admin level access across the CrushFTP application for further compromise.\n\nOn 3 April 2025, Huntress observed in-the-wild exploitation of CVE-2025-31161, an authentication bypass vulnerability in versions of the CrushFTP software. We uncovered further post-exploitation activity leveraging the MeshCentral agent and other malware that we will discuss in [this writeup. ](https://www.huntress.com/blog/crushftp-cve-2025-31161-auth-bypass-and-post-exploitation?utm_campaign=rapid-response&utm_source=reddit&utm_medium=social) While doing some further analysis, we uncovered potential evidence of compromise as early as 30 March 2025, which seemed to be testing access, and did not spawn any external processes to CrushFTP.\n\nIn [a recent post](https://x.com/Shadowserver/status/1906753539499520064) from the ShadowServer team, they state as of March 30 there were [\\~1,500 vulnerable instances](https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/time-series/?date_range=7&host_type=src&vendor=crushftp&vulnerability=cve-2025-2825&dataset=unique_ips&limit=1000&group_by=geo&style=stacked) of CrushFTP publicly exposed to the internet.\n\nWe have published a proof of concept, IOCs, and analysis on Mesh and AnyDesk post exploitations [in this blog](https://www.huntress.com/blog/crushftp-cve-2025-31161-auth-bypass-and-post-exploitation?utm_campaign=rapid-response&utm_source=reddit&utm_medium=social).\n\n# What is CVE-2025-31161? \n\n[CVE-2025-31161](https://nvd.nist.gov/vuln/detail/CVE-2025-31161) is a **9.8 CVSS** critical severity vulnerability that affects how the CrushFTP file transfer application handles user authentication. At the time of writing, the NIST NVD entry states the description:\n\n>*CrushFTP versions 10.0.0 through 10.8.3 and 11.0.0 through 11.3.0 are affected by a vulnerability in the S3 authorization header processing that allows authentication bypass. Remote and unauthenticated HTTP requests to CrushFTP with known usernames can be used to impersonate a user and conduct actions on their behalf, including administrative actions and data retrieval.*\n\nThis vulnerability [is patched](https://www.crushftp.com/crush11wiki/Wiki.jsp?page=Update) and is mitigated in CrushFTP versions 11.3.1+ and 10.8.4+. Huntress has validated and confirmed the authentication bypass is prevented in patched versions. \n\nPlease ensure your own installations of CrushFTP are updated to the latest versions. If your CrushFTP instance is publicly exposed to the open Internet, **we strongly recommend you patch immediately.**\n\nUpon successful exploitation, an adversary may gain access to the administrator user account for the CrushFTP application, and leverage this to create new backdoor accounts, access files (upload and download), obtain code execution, and achieve full control of the vulnerable server.\n\nThe vulnerability was assigned a CVE on March 26, and the Shadowserver Foundation first reported CVE-2025-31161 exploitation activity on March 31. The exploitation of CVE-2025-31161 is indicative of a concerning trend that we’ve seen [across several incidents](https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild), where threat actors are targeting MFT platforms as a way to deliver disruptive attacks. These platforms are typically external-facing and house sensitive enterprise data, making them a favorite for threat actors. As such, prompt patching is critical. Within our partner base we have seen 148 unique endpoints with the CrushFTP software installed as a service, with 95 of these running major versions 10 and 11.  Approximately 72 different companies within our customer base were currently running unpatched versions of CrushFTP.  **Customers have been notified of the urgency to upgrade.**\n\nNumerous other security firms have discussed CVE-2025-31161 (hat tip to [Rapid7 AttackerKB](https://attackerkb.com/topics/k0EgiL9Psz/cve-2025-2825/rapid7-analysis) and [Outpost24](https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/) amongst others) and thanks to their shared insights, Huntress was able to recreate a proof-of-concept (PoC) with ease. The core of this vulnerability is the S3 authentication functionality included as a part of CrushFTP. Due to logic bugs in the underlying source code (which [Project Discovery did a fantastic job](https://projectdiscovery.io/blog/crushftp-authentication-bypass) outlining), a mere **Authorization** header in an HTTP request is all that is needed to bypass authentication without valid username or password credentials.\n\n# What is Huntress Doing? \n\nPost-exploitation efforts are already thoroughly covered by Huntress detection rules. In response to these intrusions specifically, [we crafted detectors to find child processes invoked underneath the CrushFTP service executable](https://gist.github.com/JohnHammond/a22bf3103eeb0f985cf1cef4d3fc849f#file-win_proc_creation_shell_child_process_crushftp-yml).\n\n\nFor community members not yet protected with Huntress, there are two Sigma rules available in the public SigmaHQ repository for:\n\n1. Detecting “[Remote Access Tool - MeshAgent Command Execution via MeshCentral](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_meshagent_exec.yml)”\n2. Detecting “[Remote Access Tool - AnyDesk Silent Installation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_silent_install.yml)”\n\nIf you think you could be impacted, [abuse our trial](https://www.huntress.com/start-trial?utm_campaign=rapid-response&utm_source=reddit&utm_medium=social) to quickly discover anything shady left behind.",
    "permalink": "/r/sysadmin/comments/1jrocrs/critical_vulnerability_crushftp_cve202531161_auth/",
    "timestamp": "2025-04-04T22:18:48",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 2,
      "cve-2025-29927": 1
    },
    "title": "Attention: Critical Next.js vulnerability CVE-2025-29927",
    "text": "Next.js released an alert for CVE-2025-29927 (CVSS: 9.1), a authorization bypass vulnerability, impacting the Next.js React framework.\n\nThe vulnerability has been addressed in versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3.The vulnerability could allow threat actors to bypass authorization checks performed in Next.js middleware, potentially allowing them to access sensitive web pages that are typically reserved for admins or other high-privileged users.\n\nA proof of concept (PoC) for the vulnerability has been released by security researcher Rachid Allam, indicating it is imperative that the vulnerability is patched quickly to prevent threat actors from using available information to exploit.\n\n🛡️Immediate Action: Update to the latest available versions.\n\nPrevent external user requests which contain the “x-middleware-subrequest” header from reaching your Next.js application. \n\nNotable Sources: \n\n[Next.js Alert](https://nextjs.org/blog/cve-2025-29927)\n\n[PoC Blog](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware)",
    "permalink": "/r/msp/comments/1jircuc/attention_critical_nextjs_vulnerability/",
    "timestamp": "2025-03-24T14:01:38",
    "article_text": null,
    "comments": [
      {
        "score": 17,
        "text": "This is of no help to an MSP.\n\nThis product is not a standalone product that an MSP can update. This product is middleware that might be included in larger web applications.\n\nWhich web applications? Who knows? Be afraid.\n\nIs there some signature that you can use to scan for affected versions? Who knows? Be afraid.\n\nDid you provide any IOCs? Nope. But, I suspect that you'll argue that it's all in the linked blog. True, it could be, if you're a security expert that understands JavaScript and Yara. Which is way beyond most MSPs.\n\nThis post is not informative. It is FUD based advertising.",
        "level": 0
      },
      {
        "score": 3,
        "text": "Agree. Though here's the assist for MSPs...  \nIf a client has an app that relies on next.js, you can use cloudflare to WAF it and protect yourself;  \n[https://developers.cloudflare.com/changelog/2025-03-22-next-js-vulnerability-waf/](https://developers.cloudflare.com/changelog/2025-03-22-next-js-vulnerability-waf/)\n\nBut as you said, normally in the realm of developers/programmers to deal with.",
        "level": 1
      },
      {
        "score": 3,
        "text": "Really, please don't look at vulnerable products and say \"we'll just a WAF\". The moment you give someone that option, they'll have no reason to get something patched and those WAFs are always easily bypassed.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-21333"
    ],
    "cve_counts": {
      "CVE-2025-21333": 2
    },
    "title": "CVE-2025-21333 Windows kernel heap buffer overflow analysis",
    "text": "Writeup showing how to craft a POC exploit for a windows kernel heap-based buffer overflow in the paged pool.\n\nFull POC code available here: https://github.com/MrAle98/CVE-2025-21333-POC",
    "permalink": "/r/ExploitDev/comments/1jab3rz/cve202521333_windows_kernel_heap_buffer_overflow/",
    "timestamp": "2025-03-13T12:45:13",
    "article_text": null,
    "comments": [
      {
        "score": 2,
        "text": "Good read",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-40893",
      "CVE-2024-40892"
    ],
    "cve_counts": {
      "CVE-2024-40892": 2,
      "CVE-2024-40893": 2
    },
    "title": "CVE-2024-40892 and CVE-2024-40893",
    "text": "I've been a Firewalla user for a few years and I'm a big fan of the hardware and mobile app.\n\nGiven they are security products, I've long thought they would benefit from undergoing an annual security audit, with the audit report published online similar to the practices of vendors such as Proton and Bitwarden.\n\nWhile searching for something today, I randomly found [this write up](https://www.labs.greynoise.io/grimoire/2024-08-20-bluuid-firewalla/) from GreyNoise regarding vulnerabilities CVE-2024-40892 and CVE-2024-40893, which were patched in [app version 1.62](https://help.firewalla.com/hc/en-us/articles/30599664470419-Firewalla-App-Release-1-62-Support-for-Gold-Pro-Live-Throughput-by-Device-Excluding-Devices):\n\nI'm not sharing this to sensationalise the vulnerabilities but I believe if a researcher can find these issues while explicitly scoped to bluetooth functionality, a more comprehensive audit could potentially find more concerning issues that once fixed, would benefit all users.",
    "permalink": "/r/firewalla/comments/1jd9ste/cve202440892_and_cve202440893/",
    "timestamp": "2025-03-17T10:51:25",
    "article_text": null,
    "comments": [
      {
        "score": 23,
        "text": "If you are implying annual explicit security audit will find all the CVE's, then no, that's not the case, and likely will just give you false sense of security. (Given how often zero day news you see in the press from companies that have almost infinitely amount of budget for security, this audit may work for VPN services ... that's something I can't comment)\n\nIf you are implying firewalla doesn't do annual security audits, that's not true either. We audit security explicitly with every release, and there are secure code review/test processes in place, which is likely no different than any other security company.\n\n(edit, disclaimer added, indicating my comment is strictly for security products, not related security audits to VPN services)",
        "level": 0
      },
      {
        "score": 1,
        "text": "Do you guys do checks to make sure there are no hidden Chinese backdoors like in Huawei and TP-Link?",
        "level": 1
      },
      {
        "score": 2,
        "text": "we write our own code, have code reviews, and a big portion of the code we write is open.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 1
    },
    "title": "Suspected China-Nexus Threat Actor Actively Exploiting Critical Ivanti Connect Secure Vulnerability (CVE-2025-22457)",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1jqjnga/suspected_chinanexus_threat_actor_actively/",
    "timestamp": "2025-04-03T14:18:13",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "You can use this python vulnerability scanner to check if vulnerable: [https://github.com/securekomodo/CVE-2025-22457](https://github.com/securekomodo/CVE-2025-22457)\n\nAnd when you run it, the appliance will generate log ERROR31093: Program web recently failed. and is a high fidelity log to alert on to determine if being exploited by CVE-2025-22457",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-24813"
    ],
    "cve_counts": {
      "CVE-2025-24813": 1
    },
    "title": "Analysis of CVE-2025-24813 Apache Tomcat Path Equivalence RCE",
    "text": "",
    "permalink": "/r/netsec/comments/1j9f0ur/analysis_of_cve202524813_apache_tomcat_path/",
    "timestamp": "2025-03-12T08:00:26",
    "article_text": null,
    "comments": [
      {
        "score": 2,
        "text": "How does CVE-2025-24813 only have [a CVSS score of 5.5](https://nvd.nist.gov/vuln/detail/CVE-2025-24813) with C/I/A all being Low... For a RCE?",
        "level": 0
      },
      {
        "score": 3,
        "text": "It looks like somebody woke up and it's now a 9.8",
        "level": 1
      },
      {
        "score": 1,
        "text": "Aaah - So it does! :)",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-2748"
    ],
    "cve_counts": {
      "CVE-2025-2748": 1
    },
    "title": "XSS To RCE By Abusing Custom File Handlers - Kentico Xperience CMS (CVE-2025-2748) - watchTowr Labs",
    "text": "",
    "permalink": "/r/netsec/comments/1jos2z2/xss_to_rce_by_abusing_custom_file_handlers/",
    "timestamp": "2025-04-01T10:12:46",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1
    },
    "title": "Doing the Due Diligence: Analyzing the Next.js Middleware Bypass (CVE-2025-29927)",
    "text": "",
    "permalink": "/r/netsec/comments/1jim7sp/doing_the_due_diligence_analyzing_the_nextjs/",
    "timestamp": "2025-03-24T08:52:06",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32101"
    ],
    "cve_counts": {
      "CVE-2025-32101": 1
    },
    "title": "[CVE-2025-32101] UNA CMS <= 14.0.0-RC4 PHP Object Injection",
    "text": "",
    "permalink": "/r/netsec/comments/1jto4br/cve202532101_una_cms_1400rc4_php_object_injection/",
    "timestamp": "2025-04-07T15:32:26",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-24801",
      "CVE-2025-24799"
    ],
    "cve_counts": {
      "CVE-2025-24799": 1,
      "CVE-2025-24801": 1
    },
    "title": "Pre-authentication SQL injection to RCE in GLPI (CVE-2025-24799/CVE-2025-24801)",
    "text": "",
    "permalink": "/r/netsec/comments/1j9hcdw/preauthentication_sql_injection_to_rce_in_glpi/",
    "timestamp": "2025-03-12T10:53:57",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "How are there still preauth vulns in GLPI is beyond me.",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2021-35587"
    ],
    "cve_counts": {
      "CVE-2021-35587": 3,
      "cve-2021-35587": 2
    },
    "title": "Oracle Breach - Looking Like CVE-2021-35587",
    "text": "What's up peeps.\nI want to keep this short, but here's some good info I've dug up. I hate to spam the sub with more posts about the same thing, but felt this should be shared.\n\n1) The endpoint the TA stated they compromised is currently down. But there is a recent archive of it (Feb 17th) on the Wayback Machine: [https://web.archive.org/web/20250217171149/https://login.us2.oraclecloud.com/](https://web.archive.org/web/20250217171149/https://login.us2.oraclecloud.com/)\n\n2) The alleged vulnerability is CVE-2021-35587. It relates to the OpenSSO component of OAM (Oracle Access Manager). OpenSSO was deprecated in later 12c releases, but is fully available in 11g (see the Wayback Machine title? WELCOME TO ORACLE FUSION MIDDLEWARE 11g). Fun fact, 11g was deprecated in 2020.\n\n3) An interesting PoC for CVE-2021-35587 can be found here: [https://testbnull.medium.com/oracle-access-manager-pre-auth-rce-cve-2021-35587-analysis-1302a4542316](https://testbnull.medium.com/oracle-access-manager-pre-auth-rce-cve-2021-35587-analysis-1302a4542316)\n\nHope some of this can be helpful to others. Every day is looking worse for Oracle as they keep their head buried in the sand.",
    "permalink": "/r/cybersecurity/comments/1jjndqo/oracle_breach_looking_like_cve202135587/",
    "timestamp": "2025-03-25T16:23:42",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1,
      "cve-2025-29927": 1
    },
    "title": "Next.js Middleware Authentication Bypass Vulnerability (CVE-2025-29927) - Simplified With Working Demo 🕵️",
    "text": "I've created a comprehensive yet simple explanation of the critical Next.js middleware vulnerability that affects millions of applications.\n\nPlease take a look and let me know what are your thoughts 💭 \n\n📖 https://neoxs.me/blog/critical-nextjs-middleware-vulnerability-cve-2025-29927-authentication-bypass",
    "permalink": "/r/Hacking_Tutorials/comments/1jjdod8/nextjs_middleware_authentication_bypass/",
    "timestamp": "2025-03-25T07:14:26",
    "article_text": null,
    "comments": [
      {
        "score": 2,
        "text": "The vulnerable code was originally introduced as a solution to prevent infinite middleware recursion.\n\nIn the version prior to the patched one, a condition was added to track the number of discovered middleware instances and set a maximum depth of 5. This depth was stored in a specific header. However, a developer—who was apparently “vibe coding”—added a condition to completely skip the middleware if its depth exceeded 5.\n\nThe security researcher later discovered this vulnerability when they noticed an unusual header being sent with each request. Since Next.js is open-source, they reviewed the code, identified the issue, and the rest is history.\n\nYou can check the vulnerable code here:\n\nhttps://github.com/vercel/next.js/blob/4386a87db6a2b4e5464c4be1d04346653d39de11/packages/next/src/server/web/sandbox/sandbox.ts#L96",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 2
    },
    "title": "Stack-based buffer overflow in Ivanti Connect Secure - CVE-2025-22457",
    "text": "CVE-2025-22457: Stack-based buffer overflow in Ivanti Connect Secure (≤22.7R2.5), Policy Secure & ZTA Gateways could lead to remote code execution\n\nCVSS: 9.0\n\nlimited exploitation observed.",
    "permalink": "/r/cybersecurity/comments/1jr2qz7/stackbased_buffer_overflow_in_ivanti_connect/",
    "timestamp": "2025-04-04T03:49:18",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "You can use this python vulnerability scanner to check if vulnerable: [https://github.com/securekomodo/CVE-2025-22457](https://github.com/securekomodo/CVE-2025-22457)",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1
    },
    "title": "Next.js security alert - how to attack and fix CVE-2025-29927",
    "text": "",
    "permalink": "/r/pwnhub/comments/1jritd3/nextjs_security_alert_how_to_attack_and_fix/",
    "timestamp": "2025-04-04T18:21:38",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29824"
    ],
    "cve_counts": {
      "CVE-2025-29824": 1
    },
    "title": "Microsoft fixes actively exploited Windows CLFS zero-day (CVE-2025-29824)",
    "text": "",
    "permalink": "/r/cybersecurity/comments/1julxtw/microsoft_fixes_actively_exploited_windows_clfs/",
    "timestamp": "2025-04-08T19:15:37",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1
    },
    "title": "Next.js CVE-2025-29927",
    "text": "",
    "permalink": "/r/nextjs/comments/1jhgg9b/nextjs_cve202529927/",
    "timestamp": "2025-03-22T19:26:41",
    "article_text": null,
    "comments": [
      {
        "score": 8,
        "text": "That timeline is insane. It took you over two weeks from the report date to start triaging one of the worst vulnerabilities I have ever seen. If this is not a wake up call to people that Vercel does not take their backend capabilities seriously I don’t know what is.",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 1
    },
    "title": "Ivanti VPN customers targeted via unrecognized RCE vulnerability (CVE-2025-22457)",
    "text": "",
    "permalink": "/r/ivanti/comments/1jqpgu3/ivanti_vpn_customers_targeted_via_unrecognized/",
    "timestamp": "2025-04-03T18:02:53",
    "article_text": null,
    "comments": [
      {
        "score": 2,
        "text": "You can use this python vulnerability scanner to check if vulnerable: [https://github.com/securekomodo/CVE-2025-22457](https://github.com/securekomodo/CVE-2025-22457)",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1
    },
    "title": "Small demo of CVE-2025-29927. Also my first youtube video",
    "text": "Created a small video where I demo the vulnerability. Hope the language and content is simple enough for anyone to understand.\n\nhttps://youtu.be/5j8aJiKrbgU?si=NS3pUvGyGHzFAbsz",
    "permalink": "/r/nextjs/comments/1jsbznk/small_demo_of_cve202529927_also_my_first_youtube/",
    "timestamp": "2025-04-05T19:51:47",
    "article_text": null,
    "comments": [
      {
        "score": 3,
        "text": "Why is the wheel being reinvented every few hours?\n\nWe know the vulnerability. We know how it works. That vulnerability has been patched. End of story. \n\nThanks for coming to my TED Talk. \n\nps: Also, this is some low quality video with a crappy AI voiceover slapped over it, probably reading off a script generated with ChatGPT.",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 1
    },
    "title": "April Security Advisory Ivanti Connect Secure, Policy Secure & ZTA Gateways (CVE-2025-22457)",
    "text": "",
    "permalink": "/r/worldTechnology/comments/1jr57dc/april_security_advisory_ivanti_connect_secure/",
    "timestamp": "2025-04-04T06:19:17",
    "article_text": null,
    "comments": [
      {
        "score": 2,
        "text": "You can use this python vulnerability scanner to check if vulnerable: [https://github.com/securekomodo/CVE-2025-22457](https://github.com/securekomodo/CVE-2025-22457)",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2023-24932"
    ],
    "cve_counts": {
      "CVE-2023-24932": 4
    },
    "title": "Struggling with CVE-2023-24932 (BlackLotus)",
    "text": "We have around 1,500 notebooks. I've been struggling with the patch since October due to the 4x (or 8x) reboots required for the workaround.\n\nThis week, I discovered on the MS Security page that the February update has closed this vulnerability.\n\n*\"Feb 11, 2025*\n\n*The following updates have been made to CVE-2023-24932: 1) In the Security Updates table, added all supported versions of the following as they are affected by this vulnerability: Windows 11 24H2 and Windows Server 2025. 2) Further, to comprehensively address this vulnerability, Microsoft has released February 2025 security updates for all affected versions of Windows 11 version 22H2 and Windows 11 version 23H2.*\n\n*Microsoft recommends that customers install the updates to be fully protected from the vulnerability. Customers whose systems are configured to receive automatic updates do not need to take any further action.\" Source:* [CVE-2023-24932 - Security Update Guide - Microsoft - Secure Boot Security Feature Bypass Vulnerability](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-24932%22msrc.microsoft.com%22)\n\n The updates that have been installed this year:\n\n*2025-03 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5053602)*\n\n*Successfully installed on 12.03.2025*\n\n*2025-02 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5051989)*\n\n*Successfully installed on 15.02.2025*\n\n*2025-01 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5050021)*\n\n*Successfully installed on 15.01.2025*\n\n\n\nUnfortunately, it was still the old one. \n\nRunning this command - output -> True\n\n\\[System.Text.Encoding\\]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'\n\nMounting the EFI file and checking the certificate chain --> Still the 2011 certificate.\n\n It should have been the \"***Windows UEFI CA 2023***\" \n\n  \nNow I'm wondering if this was solved or not? Has anyone else checked this too?\n\n  \nThanks in Advance!!\n\n  \n\n\n  \n\n\n",
    "permalink": "/r/sysadmin/comments/1jlwbjj/struggling_with_cve202324932_blacklotus/",
    "timestamp": "2025-03-28T14:26:38",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "This is my interpretation of the entire thing (subject to potential error) as I've not seen a lot of discussion around it, outside of a few threads on the SCCM reddit.\n\nThe update doesn't change what files were signed with the cert (at the time) when you first built the device.  \nYou need to make this change.\n\n[How to manage the Windows Boot Manager revocations for Secure Boot changes associated with CVE-2023-24932 - Microsoft Support](https://support.microsoft.com/en-gb/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#bkmk_scopeofimpact)\n\nScroll down to mitigation deployment guidelines and it tells you what to do there which, doing this for 1500 machines will take you ages, so an alternative way;\n\nI tried updating our winPE addon as we use SCCM but despite following their instructions, it still shows the old cert though unless i've done something wrong, if anyone else has managed to get the new cert showing for their PE addon, please post and save me.\n\n[WinPE: Mount and Customize | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-mount-and-customize?view=windows-11#add-updates-to-winpe-if-needed)\n\nand step 6 here;\n\n[WinPE: Create bootable media | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-create-usb-bootable-drive?view=windows-11#update-the-windows-pe-add-on-for-the-windows-adk)\n\nif it was at least in the image, thats half of it effectively done (not including the reimaging your devices part) and you just have to enable the revocation part via registry which you could do with group policy.\n\nThe idea was in my situation, to include this update whilst we're reimaging devices which over time would cover a fair chunk and then manually do the rest. But no dice.\n\nEdit: used the wrong update when updating WinPE, in the latest version, also had the wrong ADK/winPE",
        "level": 0
      },
      {
        "score": 1,
        "text": "Good point, but I don't understand why Microsoft declares the vulnerability to be fixed, although this is not the case.\n\nI have tested a PS script on 2 clients, but the multiple restarts break my neck. Especially as our employees are consultants who sometimes have their notebooks in sleep mode for many weeks.\n\nWhen I make the PS prompt, the 2023 CA is shown, but it has not been implemented? Something must have changed here.\n\nPS prompt: \\[System.Text.Encoding\\]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'\n\nOutput: true\n\nThe new CA is in the repository but not implemented?...\n\nI have tried to deploy the PS script via Ivanti DSM. When the script runs through, the status is set to Undone with the feedback e.g. “Step 1 finished, Reboot Count: 0” this is then always counted up, but I cannot rebuild the reboot count correctly, because the Ivanti DSM agent on the client also starts after the sleep mode is awakened...",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-0927"
    ],
    "cve_counts": {
      "CVE-2025-0927": 1
    },
    "title": "Learn how an out-of-bounds write vulnerability in the Linux kernel can be exploited to achieve an LPE (CVE-2025-0927)",
    "text": "",
    "permalink": "/r/netsec/comments/1je3w9o/learn_how_an_outofbounds_write_vulnerability_in/",
    "timestamp": "2025-03-18T12:35:42",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 1
    },
    "title": "CVE-2025-22457: Stack-based buffer overflow in Ivanti Connect Secure",
    "text": "",
    "permalink": "/r/vulnintel/comments/1jr2mpg/cve202522457_stackbased_buffer_overflow_in_ivanti/",
    "timestamp": "2025-04-04T03:42:39",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "You can use this python vulnerability scanner to check if vulnerable: [https://github.com/securekomodo/CVE-2025-22457](https://github.com/securekomodo/CVE-2025-22457)",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-0132"
    ],
    "cve_counts": {
      "CVE-2024-0132": 1
    },
    "title": "Incomplete Patch in NVIDIA Toolkit Leaves CVE-2024-0132 Open to Container Escapes",
    "text": "",
    "permalink": "/r/u_TheCyberSecurityHub/comments/1jvzyuq/incomplete_patch_in_nvidia_toolkit_leaves/",
    "timestamp": "2025-04-10T14:58:04",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2021-35587"
    ],
    "cve_counts": {
      "CVE-2021-35587": 2
    },
    "title": "Oracle Data Breach 2025 — CVE-2021-35587 Exploited. Could Your Business Be Next?",
    "text": "The recent Oracle data breach was traced back to an older vulnerability (CVE-2021-35587), reminding us how dangerous unpatched systems and shadow IT can be.\n\nhttps://preview.redd.it/f9op8xqvg0ue1.png?width=1200&format=png&auto=webp&s=c3fa06d53d675b7688122ed927cfa9e66c7a0c0c\n\n🚨 Data was stolen  \n💼 Lawsuits are stacking up  \n🔍 Shadow IT is being blamed\n\nWhat can companies do **now** to avoid a similar fate?\n\n* Improve vulnerability monitoring\n* Use VPNs to secure remote access\n* Adopt a proactive threat model\n\nWe’re exploring how white-label VPN solutions can help businesses prevent data exfiltration and regain control. Thoughts?",
    "permalink": "/r/PureWhiteLabel/comments/1jvy5zt/oracle_data_breach_2025_cve202135587_exploited/",
    "timestamp": "2025-04-10T13:40:18",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32027"
    ],
    "cve_counts": {
      "CVE-2025-32027": 1
    },
    "title": "CVE Alert: CVE-2025-32027",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jwhw7y/cve_alert_cve202532027/",
    "timestamp": "2025-04-11T04:50:16",
    "article_text": "Yii is an open source PHP web framework. Prior to 1.1.31, yiisoft/yii is vulnerable to Reflected XSS in specific scenarios where the fallback error renderer is used. Upgrade yiisoft/yii to version 1.1.31 or higher.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-1974"
    ],
    "cve_counts": {
      "CVE-2025-1974": 2
    },
    "title": "CVE-2025-1974: PoC for the IngressNightmare (CVE-2025-1974 ) vulnerability found in the Kubernetes ingress-nginx Admission Controller",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1jkwo37/cve20251974_poc_for_the_ingressnightmare/",
    "timestamp": "2025-03-27T05:19:14",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 5
    },
    "title": "GitHub - securekomodo/CVE-2025-22457: CVE-2025-22457: Python Exploit POC Scanner to Detect Ivanti Connect Secure RCE",
    "text": "If your hunting any programs where there are Ivanti VPN appliances, this is a POC I just posted to validate if vulnerable to the buffer overflow.  \n  \nShodan Query: `http.favicon.hash:-485487831`  \nGithub: [https://github.com/securekomodo/CVE-2025-22457](https://github.com/securekomodo/CVE-2025-22457) Happy hunting!  \n  \nBlue Team Bonus. When you run it, the appliance will generate log `ERROR31093: Program web recently failed.` and is a high fidelity log for the company to validate/determine if being exploited by CVE-2025-22457.",
    "permalink": "/r/bugbounty/comments/1jvq18l/github_securekomodocve202522457_cve202522457/",
    "timestamp": "2025-04-10T05:01:04",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-1424"
    ],
    "cve_counts": {
      "CVE-2025-1424": 1
    },
    "title": "New Root Access Vulnerability For Inkpad Color 3 CVE-2025-1424",
    "text": "",
    "permalink": "/r/pocketbook/comments/1j8t7yw/new_root_access_vulnerability_for_inkpad_color_3/",
    "timestamp": "2025-03-11T15:20:11",
    "article_text": null,
    "comments": [
      {
        "score": 3,
        "text": "Hm, as far as I know, the pin code protection was added just a few moths ago. So previously anyone was able to see the on-device files by just finding the device on the street 🙂 In addition, not sure if the books on the reader are the some kind of the 'sensetive' information.",
        "level": 0
      },
      {
        "score": 1,
        "text": "Well they certainly could be sensitive especially with current politics\n\nImagine being a child learning about their gender and sexuality? Or a pregnant woman trying to find out about abortion options?\n\nFinding those sorts of books on their ereaders could be problematic.",
        "level": 1
      },
      {
        "score": 1,
        "text": "You are right. But approx.6 month ago there was no any protection at all, and now the 'advanced' level knowledge in programming is required to find out the info about the content.",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-21594"
    ],
    "cve_counts": {
      "CVE-2025-21594": 1
    },
    "title": "CVE Alert: CVE-2025-21594",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jw6zg3/cve_alert_cve202521594/",
    "timestamp": "2025-04-10T19:50:20",
    "article_text": "An Improper Check for Unusual or Exceptional Conditions vulnerability in the pfe (packet forwarding engine) of Juniper Networks Junos OS on MX Series causes a port within a pool to be blocked leading to Denial of Service (DoS). In a DS-Lite (Dual-Stack Lite) and NAT (Network Address Translation) scenario, when crafted IPv6 traffic is received and prefix-length is set to 56, the ports assigned to the user will not be freed. Eventually, users cannot establish new connections. Affected FPC/PIC need to be manually restarted to recover. Following is the command to identify the issue: user@host> show services nat source port-block Host_IP External_IP Port_Block Ports_Used/ Block_State/ Range Ports_Total Left_Time(s) 2001:: x.x.x.x 58880-59391 256/256*1 Active/- >>>>>>>>port still usedThis issue affects Junos OS on MX Series: * from 21.2 before 21.2R3-S8, * from 21.4 before 21.4R3-S7, * from 22.1 before 22.1R3-S6, * from 22.2 before 22.2R3-S4, * from 22.3 before 22.3R3-S3, * from 22.4 before 22.4R3-S2, * from 23.2 before 23.2R2-S1, * from 23.4 before 23.4R1-S2, 23.4R2. This issue does not affect versions before 20.2R1.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-0132"
    ],
    "cve_counts": {
      "CVE-2024-0132": 1
    },
    "title": "Incomplete Patch in NVIDIA Toolkit Leaves CVE-2024-0132 Open to Container Escapes",
    "text": "",
    "permalink": "/r/InfoSecNews/comments/1jw56la/incomplete_patch_in_nvidia_toolkit_leaves/",
    "timestamp": "2025-04-10T18:34:54",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-2632"
    ],
    "cve_counts": {
      "CVE-2025-2632": 1
    },
    "title": "CVE Alert: CVE-2025-2632",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jvzsad/cve_alert_cve20252632/",
    "timestamp": "2025-04-10T14:50:16",
    "article_text": "Out of bounds write vulnerability due to improper bounds checking in NI LabVIEW reading CPU info from cache that may result in information disclosure or arbitrary code execution. Successful exploitation requires an attacker to get a user to open a specially crafted VI. This vulnerability affects NI LabVIEW 2025 Q1 and prior versions.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30655"
    ],
    "cve_counts": {
      "CVE-2025-30655": 1
    },
    "title": "CVE Alert: CVE-2025-30655",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jvu2j3/cve_alert_cve202530655/",
    "timestamp": "2025-04-10T09:50:16",
    "article_text": "An Improper Check for Unusual or Exceptional Conditions vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS and Junos OS Evolved allows a local, low-privileged attacker to cause a Denial-of-Service (DoS). When a specific “show bgp neighbor” CLI command is run, the rpd cpu utilization rises and eventually causes a crash and restart. Repeated use of this command will cause a sustained DoS condition. The device is only affected if BGP RIB sharding and update-threading is enabled. This issue affects Junos OS: * All versions before 21.2R3-S9, * from 21.4 before 21.4R3-S8, * from 22.2 before 22.2R3-S6, * from 22.4 before 22.4R3-S2, * from 23.2 before 23.2R2-S3, * from 23.4 before 23.4R2. and Junos OS Evolved: * All versions before 21.2R3-S9-EVO, * from 21.4-EVO before 21.4R3-S8-EVO, * from 22.2-EVO before 22.2R3-S6-EVO, * from 22.4-EVO before 22.4R3-S2-EVO, * from 23.2-EVO before 23.2R2-S3-EVO, * from 23.4-EVO before 23.4R2-EVO.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30406"
    ],
    "cve_counts": {
      "CVE-2025-30406": 1
    },
    "title": "CVE-2025-30406 - Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025.",
    "text": "",
    "permalink": "/r/worldTechnology/comments/1jv227b/cve202530406_gladinet_centrestack_through/",
    "timestamp": "2025-04-09T09:59:34",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-1974"
    ],
    "cve_counts": {
      "CVE-2025-1974": 1
    },
    "title": "Bitnami Ingress-nginx fix for critical CVE-2025-1974 or IngressNightmare",
    "text": "",
    "permalink": "/r/devsecops/comments/1jji04o/bitnami_ingressnginx_fix_for_critical_cve20251974/",
    "timestamp": "2025-03-25T12:19:29",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "Learn how to identify, mitigate, and patch this high-risk vulnerability today: [https://blog.abhimanyu-saharan.com/posts/ingress-nginx-cve-2025-1974-what-it-is-and-how-to-fix-it](https://blog.abhimanyu-saharan.com/posts/ingress-nginx-cve-2025-1974-what-it-is-and-how-to-fix-it)",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-48887"
    ],
    "cve_counts": {
      "CVE-2024-48887": 4
    },
    "title": "🚨 CVE-2024-48887 Fortinet FortiSwitch GUI vuln (CVSS 9.3)",
    "text": "CVE-2024-48887 Fortinet FortiSwitch GUI vuln (CVSS 9.3)\n\nA remote attacker can change admin passwords without authentication via the set\\_password endpoint.\n\nUnauthenticated access + no verification = full control.\n\n[https://vulmon.com/vulnerabilitydetails?qid=CVE-2024-48887](https://vulmon.com/vulnerabilitydetails?qid=CVE-2024-48887)",
    "permalink": "/r/vulnintel/comments/1jv02nf/cve202448887_fortinet_fortiswitch_gui_vuln_cvss_93/",
    "timestamp": "2025-04-09T07:30:12",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-0124"
    ],
    "cve_counts": {
      "CVE-2025-0124": 1
    },
    "title": "[Palo Alto Networks Security Advisories] CVE-2025-0124 PAN-OS: Authenticated File Deletion Vulnerability on theManagement Web Interface",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jvbe3z/palo_alto_networks_security_advisories/",
    "timestamp": "2025-04-09T17:23:59",
    "article_text": "None",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-1073"
    ],
    "cve_counts": {
      "CVE-2025-1073": 1
    },
    "title": "CVE Alert: CVE-2025-1073",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jwrqd6/cve_alert_cve20251073/",
    "timestamp": "2025-04-11T14:50:16",
    "article_text": "Panasonic IR Control Hub (IR Blaster) versions 1.17 and earlier may allow an attacker with physical access to load unauthorized firmware onto the device.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 2
    },
    "title": "CVE-2025-22457: PoC for CVE-2025-22457 - A remote unauthenticated stack based buffer overflow affecting Ivanti Connect Secure, Pulse Connect Secure, Ivanti Policy Secure, and ZTA Gateway",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1jwrm68/cve202522457_poc_for_cve202522457_a_remote/",
    "timestamp": "2025-04-11T14:45:13",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2018-3646"
    ],
    "cve_counts": {
      "CVE-2018-3646": 1
    },
    "title": "PLEASE HELP, EVENT VIEWER WEIRD ERROR LOGS.",
    "text": "\nPlease help me, I have been having so many event viewer weird errors and my mom got me this laptop I have no idea what's wrong with it, it's only 5 months old and I don't know what to do.\n\nEvent viewer errors:\n\nThe driver/Driver/WUDFRd failed to load. Device: ROOT\\DISPLAY\\0000\n\nUMDF reflector is unable to connect to SCM. This is expected during boot, when csm has not started yet. Will retry when it starts.\n\nDevice association detected an endpoint discovery failure.\n\nThe time provider VMICTimeProvider has indicated that the current hardware and os is not supported and stopped.\n\nUnable to load pluton-windows firmware. Status code STATUS_SUCCESS. Reason: failed to apply firmware.\n\nHypervisor configured mitigations for CVE-2018-3646 for virtual machines. Processor not affected: false Processor family not affected: false Processor supports cache flush: false Hyper threading enabled: true Parent supervisor applies mitiqations: false Mitiqations disabled by bcdedit: false Mitiqations enabled: true Cache flush needed: false\n\nPlease help me, there's so many and I don't know what's wrong omg. This laptop is from Walmart and no I halvent done anything for this to happen please anyone help me out.",
    "permalink": "/r/computers/comments/1jwrlgf/please_help_event_viewer_weird_error_logs/",
    "timestamp": "2025-04-11T14:44:23",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 1
    },
    "title": "CVE-2025-22457 - Ivanti - rapid analysis",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1jwrk87/cve202522457_ivanti_rapid_analysis/",
    "timestamp": "2025-04-11T14:42:51",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2018-3646"
    ],
    "cve_counts": {
      "CVE-2018-3646": 1
    },
    "title": "Laptop is having weird event viewer logs please help me out.",
    "text": "Please help me, I have been having so many event viewer weird errors and my mom got me this laptop I have no idea what's wrong with it, it's only 5 months old and I don't know what to do.\n\nEvent viewer errors:\n\nThe driver/Driver/WUDFRd failed to load. Device: ROOT\\DISPLAY\\0000\n\nUMDF reflector is unable to connect to SCM. This is expected during boot, when csm has not started yet. Will retry when it starts.\n\nDevice association detected an endpoint discovery failure.\n\nThe time provider VMICTimeProvider has indicated that the current hardware and os is not supported and stopped.\n\nUnable to load pluton-windows firmware. Status code STATUS_SUCCESS. Reason: failed to apply firmware.\n\nHypervisor configured mitigations for CVE-2018-3646 for virtual machines.\nProcessor not affected: false\nProcessor family not affected: false\nProcessor supports cache flush: false\nHyper threading enabled: true\nParent supervisor applies mitiqations: false\nMitiqations disabled by bcdedit: false\nMitiqations enabled: true\nCache flush needed: false\n\nPlease help me, there's so many and I don't know what's wrong omg. This laptop is from Walmart and no I halvent done anything for this to happen please anyone help me out.",
    "permalink": "/r/laptops/comments/1jwrear/laptop_is_having_weird_event_viewer_logs_please/",
    "timestamp": "2025-04-11T14:35:42",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-2075",
      "CVE-2025-24813"
    ],
    "cve_counts": {
      "CVE-2025-2075": 1,
      "CVE-2025-24813": 1
    },
    "title": "Security Watch 4/11/25",
    "text": "On K12TechPro, we've launched a weekly cyber threat intelligence and vulnerability newsletter with NTP and K12TechPro. We'll post the \"public\" news to k12sysadmin from each newsletter. For the full \"k12 techs only\" portion (no middle schoolers, bad guys, vendors, etc. allowed), log into [k12techpro.com](http://k12techpro.com) and visit the Cybersecurity Hub.\n\n**Oracle Data Breach**\n\nOracle is quietly acknowledging aspects of their data breach incident following increased media pressure and a class action lawsuit.\n\n**Fast Flux**\n\nFast flux attacks are using rapid DNS changes and dummy servers to evade detection and bypass domain-level blocking. With phishing campaigns and malware delivery becoming harder to stop, here is actionable guidance from CISA on how to identify and mitigate fast flux threats across your network - [https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-093a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-093a)\n\n**Wordpress**\n\nWordPress plugin vulnerability (CVE-2025-2075) is affecting over 50,000 sites using the Uncanny Automator plugin. This flaw allows attackers with minimal access to gain full administrative privileges. \n\n**Apache Tomcat**\n\nApache Tomcat path equivalence vulnerability (CVE-2025-24813) is rated critical with a CVSS score of 9.8. This issue could allow attackers to bypass access controls or even execute remote code under specific conditions.",
    "permalink": "/r/k12sysadmin/comments/1jwr2vj/security_watch_41125/",
    "timestamp": "2025-04-11T14:22:05",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30208"
    ],
    "cve_counts": {
      "CVE-2025-30208": 2
    },
    "title": "ViteJS CVE-2025-30208",
    "text": "🚨 New plugin for ViteJS's CVE-2025-30208  is up.\n\nIt's dev, nothing wrong can happen right?\n\nHave fun.\n\nSource: https://x.com/phithon_xg/status/1905351732500250711",
    "permalink": "/r/LeakIX/comments/1jwslq4/vitejs_cve202530208/",
    "timestamp": "2025-04-11T15:27:16",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2020-11971"
    ],
    "cve_counts": {
      "CVE-2020-11971": 1
    },
    "title": "Apache Camel NES: Extended Support for EOL Camel 3.x Applications",
    "text": "For teams concerned about Apache Camel 3.x approaching end-of-life, I wanted to share that HeroDevs has just launched Apache Camel NES (Never-Ending Support).\n\n**What Apache Camel NES provides:**\n\n* Security patches for newly discovered vulnerabilities in Camel 3.x\n* Compliance documentation for SOC 2, HIPAA, and PCI-DSS\n* Support for specific Camel 3.x + Spring Boot combinations\n* Regular updates and SBOMs for security teams\n\n**Technical details:**\n\n* Version 3.22 was expected to reach EOL in December 2024\n* We also support Camel 2.25.4 (last released May 28, 2021)\n* Support for camel-spring-boot-starter:3.22.x with Spring Boot 2.7.x\n* Addresses specific vulnerabilities like CVE-2020-11971\n\nThis approach lets teams maintain security while planning migrations on their own timelines.\n\nIf anyone has questions about the technical aspects of maintaining EOL frameworks or wants to discuss Apache Camel migration challenges, I'm happy to chat.\n\nHave you found particular strategies effective for managing the transition?",
    "permalink": "/r/OSS_EOL/comments/1jwvbap/apache_camel_nes_extended_support_for_eol_camel/",
    "timestamp": "2025-04-11T17:20:52",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32242"
    ],
    "cve_counts": {
      "CVE-2025-32242": 1
    },
    "title": "CVE Alert: CVE-2025-32242",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jwyupl/cve_alert_cve202532242/",
    "timestamp": "2025-04-11T19:50:15",
    "article_text": "Missing Authorization vulnerability in Hive Support Hive Support allows Accessing Functionality Not Properly Constrained by ACLs. This issue affects Hive Support: from n/a through 1.2.2.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-22457"
    ],
    "cve_counts": {
      "CVE-2025-22457": 1
    },
    "title": "Is The Sofistication In The Room With Us? - X-Forwarded-For and Ivanti Connect Secure (CVE-2025-22457)",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1jx4140/is_the_sofistication_in_the_room_with_us/",
    "timestamp": "2025-04-11T23:44:13",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2023-41076"
    ],
    "cve_counts": {
      "CVE-2023-41076": 1
    },
    "title": "CVE Alert: CVE-2023-41076",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jx9i7q/cve_alert_cve202341076/",
    "timestamp": "2025-04-12T04:50:15",
    "article_text": "An app may be able to elevate privileges. This issue is fixed in macOS 14. This issue was addressed by removing the vulnerable code.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-36347"
    ],
    "cve_counts": {
      "CVE-2024-36347": 1
    },
    "title": "Gigabyte X870E Aorus Master F5 BIOS random 4d error after turning on secure boot",
    "text": "As per title. Recently updated my Gigabyte X870E Aorus Master from F5a to F5 for the \"AMD CPU microcode signature verification vulnerability (CVE-2024-36347)\" patch. Had updated AMD Chipset Driver to 7.01.08.129 before and after the F5 BIOS update. Got random 4d error on boot up, stuck on the screen with Aorus logo without the spinning wheel.\n\nTried reset BIOS to default settings, no help. Tried turning off PSU then hold power button for 30 secs, no good. Redownload and reflash F5 bios again then turn off memory restore context. Things seems to work well. On boot up the next day, remember I haven't turn on secure boot after reflashing BIOS. Turn it back on and the random 4d boot up error start happening again. Afterwards, I noticed some of the BIOS settings was changed after secure boot changes, including memory context restore changing back to auto. Turned it off, thought everything was stable. Turned on my PC the next day and it got stuck with 4d error again. Seems like there's something wrong with secure boot or the way I turned it on. User standard/custom mode both causes 4d error randomly. But when it boot successfully, everything works fine. Did a quick 30 min CPU+RAM and RAM test via OCCT and nothing was found.\n\nAny help please?",
    "permalink": "/r/gigabyte/comments/1jxaezo/gigabyte_x870e_aorus_master_f5_bios_random_4d/",
    "timestamp": "2025-04-12T05:49:22",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3422"
    ],
    "cve_counts": {
      "CVE-2025-3422": 1
    },
    "title": "CVE Alert: CVE-2025-3422",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jxdqs6/cve_alert_cve20253422/",
    "timestamp": "2025-04-12T09:50:16",
    "article_text": "The The Everest Forms – Contact Form, Quiz, Survey, Newsletter & Payment Form Builder for WordPress plugin for WordPress is vulnerable to arbitrary shortcode execution in all versions up to, and including, 3.1.1. This is due to the software allowing users to execute an action that does not properly validate a value before running do_shortcode. This makes it possible for authenticated attackers, with Subscriber-level access and above, to execute arbitrary shortcodes.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3102"
    ],
    "cve_counts": {
      "CVE-2025-3102": 1
    },
    "title": "Une faille critique dans le plugin WordPress OttoKit ( CVE-2025-3102)",
    "text": "",
    "permalink": "/r/actutech/comments/1jxhtmf/une_faille_critique_dans_le_plugin_wordpress/",
    "timestamp": "2025-04-12T13:54:13",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3434"
    ],
    "cve_counts": {
      "CVE-2025-3434": 1
    },
    "title": "CVE Alert: CVE-2025-3434",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jxj061/cve_alert_cve20253434/",
    "timestamp": "2025-04-12T14:50:16",
    "article_text": "The SMTP for Amazon SES – YaySMTP plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Email Logs in all versions up to, and including, 1.8 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-43102"
    ],
    "cve_counts": {
      "CVE-2024-43102": 1
    },
    "title": "Un nuovo script python porta l'exploit UMTX2 su Set-Top Box e sistemi Armbian",
    "text": "Best curtains shop in DubaiUn nuovo script python porta l'exploit UMTX2 su Set-Top Box e sistemi Armbianhttps://www.biteyourconsole.net/wp-content/uploads/PS5Payload.webphttps://dubaicurtainshops.com/Lo sviluppatore noto come goakal-play ha realizzato una versione personalizzata di un server host per l’exploit umtx2, pensata per funzionare su dispositivi STB (Set-Top Box) o sistemi operativi basati su Armbian, con l’intento di eseguire il jailbreak della PlayStation 5 in ambienti locali o offline.\\\nL’exploit umtx2, alla base del progetto, sfrutta la vulnerabilità CVE-2024-43102 nel WebKit della console per ottenere accesso al kernel e consentire l’esecuzione di codice non firmato, come payload homebrew o strumenti di debug.\\\nA differenza della repository originale di idlesauce, focalizzato sull’utilizzo dell’exploit tramite browser PS5 o siti ospitati su Cloudflare, questa implementazione è ottimizzata per ambienti server alternativi, come dispositivi embedded o single-board computer, tra cui Raspberry Pi.\\\nL’obiettivo è quello di fornire una soluzione autonoma e indipendente da internet, utile per chi desidera un setup permanente o privato.\\\nIl server si ispira probabilmente al file host.py di umtx2, ma è stato adeguatamente adattato per l’architettura dei dispositivi STB/Armbian.\\\nInclude uno script HTTP locale in grado di fornire l’exploit alla console, insieme a un loader ELF attivo su porte dedicate (come la 9020), necessario per inviare payload alla PS5.\\\n\\\nCaratteristiche\\\n\\\n \tAvvio automatico del server all’accensione tramite systemd.\\\n \tSpoofing DNS e gestione degli attacchi di tipo rebind.\\\n \tSupporto HTTP per l’app esphost e HTTPS per il reindirizzamento dal menu guida utente della PS5.\\\n \tLeggero e ottimizzato per dispositivi STB.\\\n\\\nNota: Questo progetto richiede che il dispositivo STB (Set-Top Box) sia preventivamente rootato. Dopo il rooting, è necessario installare correttamente Armbian prima di procedere alla configurazione.\\\nConfigurazione\\\nInstallazione delle dipendenze\\\n\\\nsudo apt update\\\nsudo apt install dnsmasq hostapd net-tools -y\\\nClonazione della repository di idlesauce\\\n\\\ngit clone https://github.com/idlesauce/umtx2.git umtx2/\\\nwget https://raw.githubusercontent.com/goakal-play/ps5-umtx2-server-stb/main/custom_host.py -P umtx2/\\\nArrestare systemd-resolved per evitare conflitti con il DNS personalizzato\\\nsudo systemctl stop systemd-resolved\\\nsudo systemctl disable systemd-resolved\\\nCreare un servizio systemd per assegnare un IP statico\\\ncat  /dev/null\\\n\\\nDescription=Set Static IP Address and restart services\\\nAfter=network-online.target hostapd.service\\\nWants=network-online.target\\\n\\\n\\\nType=oneshot\\\nExecStart=/usr/local/bin/set-static-ip.sh\\\nRemainAfterExit=yes\\\n\\\n\\\nWantedBy=multi-user.target\\\nEOF\\\nCreare uno script IP statico eseguito dal servizio sopra\\\ncat  /dev/null\\\n#!/bin/bash\\\nfor i in 1..10; do\\\n  if ip link show wlan0 > /dev/null 2>&1; then\\\n    break\\\n  fi\\\n  sleep 1\\\ndone\\\nip link set wlan0 up\\\nifconfig wlan0 10.1.1.1 netmask 255.255.255.0 up\\\nsystemctl restart hostapd\\\nsystemctl restart dnsmasq\\\nEOF\\\nRenderlo eseguibile e abilitare il servizio\\\nsudo chmod +x /usr/local/bin/set-static-ip.sh\\\nsudo systemctl daemon-reload\\\nsudo systemctl enable static-ip.service\\\nsudo systemctl start static-ip.service\\\nConfigurazione Hostapd (punto di accesso WiFi)\\\ncat  /dev/null\\\ninterface=wlan0\\\nssid=PS5_UMTX2\\\nhw_mode=g\\\nchannel=6\\\nauth_algs=1\\\nwpa=2\\\nwpa_passphrase=12345678\\\nwpa_key_mgmt=WPA-PSK\\\nrsn_pairwise=CCMP\\\nEOF\\\nCollega il file di configurazione Hostapd\\\ncat  /dev/null\\\ninterface=wlan0\\\nbind-interfaces\\\nport=0\\\ndhcp-range=10.1.1.2,10.1.1.9,7d\\\ndhcp-option=3,10.1.1.1\\\ndhcp-option=6,10.1.1.1\\\nbogus-priv\\\nno-resolv\\\nno-hosts\\\nno-poll\\\nlog-dhcp\\\nlog-queries\\\nEOF\\\nRiavvio del servizio dnsmasq\\\nsudo systemctl restart dnsmasq\\\nServizi Systemd per custom_host.py (Server)\\\ncat  /dev/null\\\n\\\nDescription=PS5 Exploit Host\\\nAfter=network.target\\\n\\\n\\\nExecStart=/usr/bin/python3 /root/umtx2/custom_host.py\\\nWorkingDirectory=/root/umtx2\\\nRestart=always\\\nUser=root\\\n\\\n\\\nWantedBy=multi-user.target\\\nEOF\\\nServizi Systemd per FakeDNS\\\ncat  /dev/null\\\n\\\nDescription=Fake DNS Server\\\nAfter=network.target\\\n\\\n\\\nExecStart=/usr/bin/python3 /root/umtx2/fakedns.py -c /root/umtx2/dns.conf\\\nWorkingDirectory=/root/umtx2\\\nRestart=always\\\n\\\n\\\nWantedBy=multi-user.target\\\nEOF\\\nCambia l'IP predefinito di dns.conf in IP STB statico\\\ncat  /dev/null\\\nA manuals.playstation.net 10.1.1.1\\\nEOF\\\nAbilita e avvia tutti i servizi\\\nsudo systemctl daemon-reexec\\\nsudo systemctl daemon-reload\\\nsudo systemctl enable ps5-host.service\\\nsudo systemctl enable fakedns.service\\\nsudo systemctl start ps5-host.service\\\nsudo systemctl start fakedns.service\\\nRiavvia il sistema\\\nsudo reboot\\\nControlla lo stato del servizio\\\nsudo systemctl status ps5-host.service\\\nsudo systemctl status fakedns.service\\\nsudo systemctl status dnsmasq.service\\\nsudo systemctl status static-ip.service\\\nDownload: PS5 UMTX2 Exploit Host Server (STB/Armbian)\\\n\\\nFonte: x.com\\\n\\\nDiscover the best curtains shop in Dubai, where style meets quality and customization. Offering a vast selection of luxurious fabrics, blackout options, and motorized systems, top curtain shops in Dubai provide tailored window treatments to match any interior. From elegant drapes to modern blinds, these stores prioritize premium craftsmanship, exceptional service, and professional installation, ensuring a perfect fit for every space. Whether you seek classic designs or contemporary aesthetics, Dubai’s curtain shops offer solutions that enhance privacy, block out light, and elevate your decor, making them the ideal choice for all your window covering needs.",
    "permalink": "/r/BiteYourConsole/comments/1jxkkwy/un_nuovo_script_python_porta_lexploit_umtx2_su/",
    "timestamp": "2025-04-12T16:01:00",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-0132"
    ],
    "cve_counts": {
      "CVE-2024-0132": 1
    },
    "title": "Incomplete NVIDIA Patch to CVE-2024-0132 Exposes AI Infrastructure and Data",
    "text": "",
    "permalink": "/r/worldTechnology/comments/1jxnf9n/incomplete_nvidia_patch_to_cve20240132_exposes_ai/",
    "timestamp": "2025-04-12T18:05:45",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30429"
    ],
    "cve_counts": {
      "CVE-2025-30429": 1
    },
    "title": "CVE-2025-30429 exploit",
    "text": "what exactly does \"an app breaking out of its sandbox\" mean and what could be done with it?",
    "permalink": "/r/jailbreak/comments/1jxn3rf/cve202530429_exploit/",
    "timestamp": "2025-04-12T17:51:53",
    "article_text": null,
    "comments": [
      {
        "score": 3,
        "text": "It means with said exploit that apps have the advantage of being able to do things outside of its permissions. Much like Filza.",
        "level": 0
      },
      {
        "score": 2,
        "text": "so, can we edit files inside /var? if so, can we make a tool like MisakaX for iOS 18.1-18.3.1?",
        "level": 1
      },
      {
        "score": 1,
        "text": "Perhaps; but it'll require much more than just one exploit..",
        "level": 2
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-32631"
    ],
    "cve_counts": {
      "CVE-2025-32631": 1
    },
    "title": "CVE Alert: CVE-2025-32631",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jxprtu/cve_alert_cve202532631/",
    "timestamp": "2025-04-12T19:50:13",
    "article_text": "Improper Limitation of a Pathname to a Restricted Directory (‘Path Traversal’) vulnerability in oxygensuite Oxygen MyData for WooCommerce allows Path Traversal. This issue affects Oxygen MyData for WooCommerce: from n/a through 1.0.63.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30406"
    ],
    "cve_counts": {
      "CVE-2025-30406": 1
    },
    "title": "Centrestack Folks - Update your servers IMMEDIATLEY CVE-2025-30406",
    "text": "In case anyone missed the 4PM EST Friday email from them, it's critical to update your servers immediately. We had 3 installs get compromised by the time we'd completed our updates.\n\nHuge shout out to Huntress as usual for catching the RCE and honorary mention to defender for killing the privilege escalation.\n\nLooks like mass recon/script kid attacks right now (they escalated to Cobalt Strike which got caught by A/V) but yeah this one is bad.",
    "permalink": "/r/msp/comments/1jy8y1k/centrestack_folks_update_your_servers_immediatley/",
    "timestamp": "2025-04-13T14:30:29",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-7971",
      "CVE-2025-3102",
      "CVE-2025-22457",
      "CVE-2025-3248",
      "CVE-2025-29824",
      "CVE-2025-30406",
      "CVE-2025-24813",
      "CVE-2023-27997",
      "CVE-2024-21762",
      "CVE-2022-42475"
    ],
    "cve_counts": {
      "CVE-2025-30406": 1,
      "CVE-2024-7971": 1,
      "CVE-2024-21762": 1,
      "CVE-2022-42475": 1,
      "CVE-2023-27997": 1,
      "CVE-2025-3248": 1,
      "CVE-2025-22457": 1,
      "CVE-2025-3102": 1,
      "CVE-2025-29824": 1,
      "CVE-2025-24813": 1
    },
    "title": "🔥 Top 10 Trending CVEs (13/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities circulating today, with CVSS scores and short summaries:\n\n**1. CVE-2025-30406**\n\n- 📝 Unpatched Gladinet CentreStack versions prior to 16.4.10315.56368 contain a server-side deserialization vulnerability, enabling remote code execution. Known to have been exploited in the wild since March 2025. The hardcoded machineKey in portal\\web.config is the attack vector. Administrators are advised to manually delete this key and apply updates. (CISA KEV: true)\n\n- 📅 **Published:** 03/04/2025\n- 📈 **CVSS:** 9\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**2. CVE-2024-7971**\n\n- 📝 Remotely exploitable, high-severity type confusion vulnerability found in V8 engine of Google Chrome (versions prior to 128.0.6613.84). The flaw allows a remote attacker to corrupt the heap via a crafted HTML page, with evidence of active exploitation reported by CISA.\n\n- 📅 **Published:** 21/08/2024\n- 📈 **CVSS:** 9.6\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H\n\n---\n\n**3. CVE-2024-21762**\n\n- 📝 A critical out-of-bounds write vulnerability (CVSS 9.8) has been identified in Fortinet FortiOS versions 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, and others, as well as FortiProxy versions with similar ranges. This issue allows an unauthenticated attacker to execute arbitrary code or commands via crafted requests, and it has been exploited in the wild (CISA KEV). Immediate patching is advised for affected systems.\n\n- 📅 **Published:** 09/02/2024\n- 📈 **CVSS:** 9.8\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**4. CVE-2022-42475**\n\n- 📝 A critical, remotely exploitable heap-based buffer overflow vulnerability (CWE-122) exists in multiple FortiOS SSL-VPN and FortiProxy SSL-VPN versions. This issue allows unauthenticated attackers to execute arbitrary code or commands via specially crafted requests, with this vulnerability confirmed to have been exploited in the wild. Immediate patching is advised for affected systems.\n\n- 📅 **Published:** 02/01/2023\n- 📈 **CVSS:** 9.8\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**5. CVE-2023-27997**\n\n- 📝 A critical, remotely exploitable heap-based buffer overflow vulnerability (CWE-122) exists in FortiOS 7.2.4 and below, 7.0.11 and below, 6.4.12 and below, 6.0.16 and below, FortiProxy 7.2.3 and below, 7.0.9 and below, 2.0.12 and below, all versions of 1.2 and all versions of 1.1, as well as SSL-VPN. The vulnerability allows an attacker to execute arbitrary code or commands via specifically crafted requests, with the CISA KEV indicating it has been exploited in the wild. Immediate patching is advised for affected systems.\n\n- 📅 **Published:** 13/06/2023\n- 📈 **CVSS:** 9.8\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**6. CVE-2025-3248**\n\n- 📝 Unauthenticated remote code execution vulnerability (CVSS 9.8) exists in Langflow versions prior to 1.3.0 via the /api/v1/validate/code endpoint, allowing an attacker to execute arbitrary code without authentication. No known exploitation in the wild reported by CISA.\n\n- 📅 **Published:** 07/04/2025\n- 📈 **CVSS:** 9.8\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**7. CVE-2025-22457**\n\n- 📝 A critical, remotely exploitable stack-based buffer overflow vulnerability (stack-buffer-overflow) exists in Ivanti Connect Secure before 22.7R2.6, Ivanti Policy Secure before 22.7R1.4, and Ivanti ZTA Gateways before 22.8R2.2. This flaw allows unauthenticated attackers to execute arbitrary code (Remote Code Execution). Notably, this vulnerability has been observed in active exploitation by threat actors (CISA Known Exploited Vulnerability). Immediate patching is strongly advised.\n\n- 📅 **Published:** 03/04/2025\n- 📈 **CVSS:** 9\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**8. CVE-2025-3102**\n\n- 📝 Unauthenticated attackers can create administrator accounts on WordPress sites using the SureTriggers plugin, version 1.0.78 and below, due to a missing empty value check on the secret_key in the authenticate_user function. This issue is remotely exploitable without requiring an API key configuration.\n\n- 📅 **Published:** 10/04/2025\n- 📈 **CVSS:** 8.1\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**9. CVE-2025-29824**\n\n- 📝 A use-after-free vulnerability (CVSS 7.8) exists within the Windows Common Log File System Driver, enabling locally authenticated attackers to elevate privileges. This issue has been observed being exploited in the wild (CISA KEV: true). Affected versions should be updated promptly.\n\n- 📅 **Published:** 08/04/2025\n- 📈 **CVSS:** 7.8\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**10. CVE-2025-24813**\n\n- 📝 A critical (CVSS 9.8) Remote Code Execution vulnerability exists in Apache Tomcat versions from 11.0.0-M1 through 11.0.2, 10.1.0-M1 through 10.1.34, and 9.0.0.M1 through 9.0.98. This issue stems from a Path Equivalence flaw in the Default Servlet, allowing unauthorized users to disclose sensitive information, inject content into files, or perform remote code execution if specific conditions are met. CISA has acknowledged that this vulnerability has been exploited in the wild. Users are advised to upgrade to versions 11.0.3, 10.1.35, or 9.0.99 for mitigation.\n\n- 📅 **Published:** 10/03/2025\n- 📈 **CVSS:** 9.8\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\nLet me know if you're tracking any of these or if something flew under the radar",
    "permalink": "/r/CVEWatch/comments/1jydv1t/top_10_trending_cves_13042025/",
    "timestamp": "2025-04-13T18:05:05",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-27480"
    ],
    "cve_counts": {
      "CVE-2025-27480": 1
    },
    "title": "Remote Desktop issues after 2025-04 CUs?",
    "text": "Anyone having issues with Remote Desktop Connection after installing the 2025-04 Cumulative Update for Windows Server? There was a fix for a RD security flaw which is tracked as CVE-2025-27480 so I am wondering if that might be the culprit. Here are some of the issues.\n\n1. When I minimize a RD session and then go back to it, i'll get a black screen for a few seconds, before the session shows up.\n2. When I try to do something in the RD session, nothing happens. Nothing is responsive for a few seconds.\n3. I'll get a message about losing connectivity and it will retry to connect (up to five attempts). It will eventually reconnect.\n\nI'm working remotely over a VPN so am thinking of going into the office and getting on the local network to see if the issue persists. Just wondering if anyone else has seen anything like this since they installed the April CUs.",
    "permalink": "/r/RemoteDesktopServices/comments/1jydc3k/remote_desktop_issues_after_202504_cus/",
    "timestamp": "2025-04-13T17:42:53",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-27480"
    ],
    "cve_counts": {
      "CVE-2025-27480": 1
    },
    "title": "Remote Desktop issues after 2025-04 CUs?",
    "text": "Anyone having issues with Remote Desktop Connection after installing the 2025-04 Cumulative Update for Windows Server? There was a fix for a RD security flaw which is tracked as CVE-2025-27480 so I am wondering if that might be the culprit. Here are some of the issues.\n\n1. When I minimize a RD session and then go back to it, i'll get a black screen for a few seconds, before the session shows up.\n2. When I try to do something in the RD session, nothing happens. Nothing is responsive for a few seconds.\n3. I'll get a message about losing connectivity and it will retry to connect (up to five attempts). It will eventually reconnect.\n\nI'm working remotely over a VPN so am thinking of going into the office and getting on the local network to see if the issue persists. Just wondering if anyone else has seen anything like this since they installed the April CUs.",
    "permalink": "/r/WindowsServer/comments/1jydbx0/remote_desktop_issues_after_202504_cus/",
    "timestamp": "2025-04-13T17:42:39",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "What Server version?",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-27480"
    ],
    "cve_counts": {
      "CVE-2025-27480": 1
    },
    "title": "Remote Desktop issues after April Cumulative Updates?",
    "text": "Anyone having issues with Remote Desktop Connection after installing the 2025-04 Cumulative Update for Windows Server?  There was a fix for a RD security flaw which is tracked as CVE-2025-27480 so I am wondering if that might be the culprit.  Here are some of the issues. \n\n1. When I minimize a RD session and then go back to it, i'll get a black screen for a few seconds, before the session shows up.\n2. When I try to do something in the RD session, nothing happens.  Nothing is responsive for a few seconds.\n3. I'll get a message about losing connectivity and it will retry to connect (up to five attempts). It will eventually reconnect.  \n\nI'm working remotely over a VPN so am thinking of going into the office and getting on the local network to see if the issue persists.  Just wondering if anyone else has seen anything like this since they installed the April CUs.",
    "permalink": "/r/sysadmin/comments/1jydaol/remote_desktop_issues_after_april_cumulative/",
    "timestamp": "2025-04-13T17:41:11",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "I don’t know about the issue as it pertains to that update but your issue 3 I was having where a perfectly fine and historically stable RDP session would timeout and reconnect every minute or so. I was able to fix the issue by forcing RDP to use TCP instead of it trying to switch to UDP automatically after about a minute. \n\n\nEdit or create the DWORD registry value fClientDisableUDP and set the value to 1\n\n\nThat DWORD should be located in HKLM\\software\\policies\\microsoft\\windows nt\\terminal services\\client\\\n\n\nDisconnect and reconnect the RDP session to use the new reg setting. \n\n\nHope it helps you as it did me.",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2023-27997",
      "CVE-2024-21762",
      "CVE-2022-42475"
    ],
    "cve_counts": {
      "CVE-2022-42475": 1,
      "CVE-2023-27997": 1,
      "CVE-2024-21762": 1
    },
    "title": "Fortinet Devices Still Vulnerable Post-Patching – Here's Why It Matters 🧵",
    "text": "Fortinet has disclosed that attackers are maintaining **read-only access** to FortiGate devices **even after** patching known CVEs like:\n\n* CVE-2022-42475\n* CVE-2023-27997\n* CVE-2024-21762\n\n🔍 How?  \nBy creating a **symbolic link (symlink)** between the user file system and root in the SSL-VPN language file folder. This survives patching and even persists after factory resets in some cases.\n\n📌 Notably, devices that never enabled **SSL-VPN** are unaffected.  \nFortinet has rolled out updates in FortiOS (7.6.2, 7.4.7, etc.) to remove the symlink and harden SSL-VPN UI.\n\n🛡️ Suggested Actions:\n\n* Upgrade to the latest FortiOS\n* Review all configurations\n* Treat settings as potentially compromised\n* Reset exposed credentials\n* Consider disabling SSL-VPN temporarily\n\n  \n\\#Cybersecurity #Fortinet #CVE #NetworkSecurity #Infosec #RedTeam",
    "permalink": "/r/cybersecurityexams/comments/1jysr7n/fortinet_devices_still_vulnerable_postpatching/",
    "timestamp": "2025-04-14T07:02:12",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-43590"
    ],
    "cve_counts": {
      "CVE-2024-43590": 8,
      "cve-2024-43590": 4
    },
    "title": "CVE-2024-43590 vulnerability not detected with wazuh",
    "text": "Hello Wazuher's,\n\n  \nsee there:\n\n[https://cti.wazuh.com/vulnerabilities/cves/CVE-2024-43590](https://cti.wazuh.com/vulnerabilities/cves/CVE-2024-43590)\n\nAnd here:\n\n[https://nvd.nist.gov/vuln/detail/cve-2024-43590](https://nvd.nist.gov/vuln/detail/cve-2024-43590)\n\n  \nBUT HERE (only corretly listed) as :\n\n  \nUpdated Microsoft **Visual C++ 2015-2022 Redistributable** version to 14.40.33816 with the fix for CVE-2024-43590. For more information on this vulnerability, see [CVE-2024-43590](https://www.cve.org/CVERecord?id=CVE-2024-43590).\n\nMeaning that in NVD Link [https://nvd.nist.gov/vuln/detail/cve-2024-43590](https://nvd.nist.gov/vuln/detail/cve-2024-43590) only refers to product (Name) **visual\\_studio (Visual studio) and its verions, it' the development tool / environment itself. But NOT the runtime version, for its complied (outcome), as far as i know.  So actually product visual studio is NOT the same as the** Visual C++ Redistributable Installer**.**\n\n**The cve.org link in below clearly listed all affected prodcuts and it's versions and diferrenciate them properly.** \n\n[https://www.cve.org/CVERecord?id=CVE-2024-43590](https://www.cve.org/CVERecord?id=CVE-2024-43590)\n\n[https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170#visual-studio-2015-2017-2019-and-2022](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170#visual-studio-2015-2017-2019-and-2022)\n\n  \nonly in above link from [cve.org](http://cve.org) is correct info, also seen in broadcom vmware tools rlease notes:\n\n[https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/tools/12-5-0/release-notes/vmware-tools-1251-release-notes.html](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/tools/12-5-0/release-notes/vmware-tools-1251-release-notes.html)\n\n  \n**Would be happy to see it's fixed.  Happy to help you to make wazuh more and more better ;)**\n\n**And kindly same goes for the more often / regulary CVE CTI Database update intervall, as e. g. current Microsoft Windows CU 2025-04 CVES are not yet included..**",
    "permalink": "/r/Wazuh/comments/1jyv7q9/cve202443590_vulnerability_not_detected_with_wazuh/",
    "timestamp": "2025-04-14T10:03:48",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2023-48795",
      "CVE-2018-15473"
    ],
    "cve_counts": {
      "CVE-2018-15473": 1,
      "CVE-2023-48795": 1
    },
    "title": "Cybersecurity: SSH Hardening & Offensive Mastery by DsDSec (Free PDF)",
    "text": "Hello everyone,\n\nI’d like to share a resource recently published by our cybersecurity group DsDSec:\n\n\"SSH Hardening & Offensive Mastery\", a free technical book focused entirely on SSH security.\n\nSSH remains a crucial access point in modern infrastructure. Properly securing it is essential, and this book aims to provide a comprehensive understanding of both its defensive and offensive aspects, going far beyond basic configurations.\n\n🔍 What the book covers:\n\n1. Defensive Hardening:\n\nSecure configurations and best practices\n\n2FA implementation\n\nFail2Ban and Suricata (IDS/IPS) integration\n\nPractical methods to strengthen SSH servers\n\n2. Offensive Techniques (with hands-on labs):\n\nAll types of SSH tunnels (local, remote, dynamic, UDP), and how to bypass restrictions\n\nEvasion of firewalls and filtering controls\n\nSSH agent hijacking\n\nMalware propagation via dynamic tunnels, with a lab using Metasploit and BlueKeep\n\nVulnerability analysis, including CVE-2018-15473 (user enumeration) and Terrapin (CVE-2023-48795)\n\nEnvironment variable abuse, such as LD\\_PRELOAD\n\nCustom tools developed in Tcl/Expect and Perl for testing and automation\n\nAlthough the book focuses on SSH, the knowledge and techniques can be applied more broadly to securing and attacking other services. It is intended for sysadmins, red and blue team professionals, and cybersecurity practitioners, from early learners to advanced users.\n\n📘 Download the full PDF (free):\n\n➡ SSH-Hardening-and-Offensive-Mastery.pdf\n\n🔗 Follow DsDSec for future updates:\n\n🌐 [https://dsdsec.com](https://dsdsec.com)\n\n🐦 [https://twitter.com/dsdsec](https://twitter.com/dsdsec)\n\n💼 [https://www.linkedin.com/company/dsdsecurity](https://www.linkedin.com/company/dsdsecurity)\n\n📺 [https://www.youtube.com/@DSDSec](https://www.youtube.com/@DSDSec)\n\n📷 [https://www.instagram.com/dsd.sec/](https://www.instagram.com/dsd.sec/)\n\nWe are currently preparing additional content. Lab walkthroughs will be published soon on YouTube.\n\nWell, friends, I hope you enjoy the book and find it useful. 😉\n\nBest regards to everyone, and thank you for your support!",
    "permalink": "/r/Hacking_Tricks/comments/1jyzi61/cybersecurity_ssh_hardening_offensive_mastery_by/",
    "timestamp": "2025-04-14T13:57:26",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30406",
      "CVE-2023-4966",
      "CVE-2022-42475",
      "CVE-2024-21762",
      "CVE-2024-7971",
      "CVE-2023-46818",
      "CVE-2025-21204",
      "CVE-2023-27997"
    ],
    "cve_counts": {
      "CVE-2024-7971": 1,
      "CVE-2025-21204": 1,
      "CVE-2023-4966": 1,
      "CVE-2025-30406": 1,
      "CVE-2023-46818": 1,
      "CVE-2024-21762": 1,
      "CVE-2022-42475": 1,
      "CVE-2023-27997": 1
    },
    "title": "🔥 Top 10 Trending CVEs (14/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. undefined**\n\n- 📝 Remotely Exploitable Vulnerability (CVSS Score: 9.8) in XYZ Library Version <3.2.1, as confirmed by CISA KEV. Affected systems may allow attackers to take full control, requiring immediate patching or mitigation measures.\n\n- 📅 **Published:** N/A\n\n---\n\n**2. CVE-2024-7971**\n\n- 📝 Remotely exploitable type confusion vulnerability in V8 engine of Google Chrome versions prior to 128.0.6613.84 allows heap corruption via a crafted HTML page. This vulnerability has been classified as high severity by Chromium and was identified in the wild by CISA.\n\n- 📅 **Published:** 21/08/2024\n- 📈 **CVSS:** 9.6\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H\n\n---\n\n**3. CVE-2025-21204**\n\n- 📝 A local privilege escalation vulnerability (CVE xxx) exists in Windows Update Stack, allowing authorized attackers to elevate privileges by improperly resolving links before file access. The CVSS score is 7.8, indicating high severity, and it appears to be remotely exploitable. At this time, there's no confirmation that it has been actively exploited in the wild. It affects specific versions as mentioned in the description.\n\n- 📅 **Published:** 08/04/2025\n- 📈 **CVSS:** 7.8\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**4. CVE-2023-4966**\n\n- 📝 A critical (CVSS 9.4) vulnerability has been identified in NetScaler ADC and Gateway, allowing unauthorized disclosure of sensitive information when configured as a gateway or AAA virtual server. This vulnerability has reportedly been exploited in the wild. It's crucial to verify if your deployed versions are affected.\n\n- 📅 **Published:** 10/10/2023\n- 📈 **CVSS:** 9.4\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L\n\n---\n\n**5. CVE-2025-30406**\n\n- 📝 A deserialization vulnerability (CVSS v3.1: 9) exists in Gladinet CentreStack versions up to and including 16.1.10296.56315, exploited since March 2025. The flaw is due to hardcoded machineKey use, allowing remote code execution by an attacker with knowledge of the machineKey, unless manually deleted from portal\\web.config. CISA has acknowledged exploitation in the wild. Administrators are advised to update to CentreStack version 16.4.10315.56368 immediately.\n\n- 📅 **Published:** 03/04/2025\n- 📈 **CVSS:** 9\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**6. CVE-2023-46818**\n\n- 📝 Remotely Exploitable Code Injection Vulnerability found in ISPConfig versions prior to 3.2.11p1, via PHP code injection in the language file editor when admin_allow_langedit is enabled. High severity (CVSS 7.2). Not yet observed in the wild by CISA. Mitigation: Upgrade to a patched version or disable admin_allow_langedit until patched.\n\n- 📅 **Published:** 27/10/2023\n- 📈 **CVSS:** 7.2\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**7. undefined**\n\n- 📝 Remotely Exploitable High Severity Vulnerability (CVSS 9.8) found in version X of Y software, as indicated by CISA KEV. Affected systems may experience unauthorized code execution if exploited. Mitigations and patches are available from the vendor.\n\n- 📅 **Published:** N/A\n\n---\n\n**8. CVE-2024-21762**\n\n- 📝 A critical (CVSS 9.8) out-of-bounds write vulnerability exists in Fortinet FortiOS and FortiProxy versions as listed, enabling unauthorized code execution via crafted requests. This vulnerability has been exploited in the wild (CISA KEV: True). Immediate patching is recommended for affected systems.\n\n- 📅 **Published:** 09/02/2024\n- 📈 **CVSS:** 9.8\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**9. CVE-2022-42475**\n\n- 📝 A critical, heap-based buffer overflow vulnerability (CWE-122) exists in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, and earlier versions, as well as FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier. This vulnerability is remotely exploitable by unauthenticated attackers, potentially allowing arbitrary code execution. The CISA has confirmed that it has been exploited in the wild. Immediate action is required for affected versions.\n\n- 📅 **Published:** 02/01/2023\n- 📈 **CVSS:** 9.8\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**10. CVE-2023-27997**\n\n- 📝 A critical, remotely exploitable heap buffer overflow vulnerability (CWE-122) exists in FortiOS versions 7.2.4 and below, 7.0.11 and below, 6.4.12 and below, 6.0.16 and below, FortiProxy versions 7.2.3 and below, 7.0.9 and below, 2.0.12 and below, 1.2 all versions, 1.1 all versions, affecting SSL-VPN. This vulnerability has been exploited in the wild (CISA KEV: true). Immediate patching is advised for affected systems.\n\n- 📅 **Published:** 13/06/2023\n- 📈 **CVSS:** 9.8\n- 🛡️ **CISA KEV:** true\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\nLet me know if you're tracking any of these or if something flew under the radar",
    "permalink": "/r/CVEWatch/comments/1jyz83k/top_10_trending_cves_14042025/",
    "timestamp": "2025-04-14T13:44:37",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-0010"
    ],
    "cve_counts": {
      "CVE-2024-0010": 1
    },
    "title": "Reflected XSS",
    "text": "For those of you out there running firewalls with a GP gateway only (no portal) check for CVE-2024-0010. It appears to me this reflected XSS attack was fixed on the portals but not the gateways. Dunno if gateways are a vector for the attack, but checking with Palo. Will report back.\n\nNote, this is not reproducible on a portal running the unaffected versions noted in the CVE.\n\nYou can test the vuln on your gateway by browsing to:\n\nhttps://your-gateway/global-protect/getconfig.esp?portal-userauthcookie=%3Csvg%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cscript%20type=%22text/javascript%22%3Econfirm(%22XSS%22)%3C/script%3E%3C/svg%3E\n\nI've been told some bug bounty outfit is already working with Palo. Dunno what this means for patching or mitigations in the short-term.",
    "permalink": "/r/paloaltonetworks/comments/1jyypca/reflected_xss/",
    "timestamp": "2025-04-14T13:20:31",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-5921"
    ],
    "cve_counts": {
      "CVE-2024-5921": 1
    },
    "title": "Good news on GP 6.2.8",
    "text": "A follow up on:\n\nhttps://www.reddit.com/r/paloaltonetworks/comments/1hal795/non_compliant_fipscc_mode_certificate/\n\nGP 6.2.8 does resolve the ECC cert issue when mitigating for CVE-2024-5921. \n\nTo summarize the issue, the mitigation steps for the mentioned CVE did not work with clients prior to 6.2.8 when using an ECC cert for the portal/gateway. Enabling the registry settings or updating the relevant plist would result in FIPS-CC validation errors. With the new client using ECC certs, the entire mitigation can be done for 2024-5921.",
    "permalink": "/r/paloaltonetworks/comments/1jz5jqj/good_news_on_gp_628/",
    "timestamp": "2025-04-14T18:06:07",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-0132"
    ],
    "cve_counts": {
      "CVE-2024-0132": 1
    },
    "title": "Nvidia Patch Incompleteness Poses Risks in AI Container Security",
    "text": "\n**Trend Micro has discovered a critical security flaw in Nvidia's patch for the Container Toolkit that still leaves AI environments vulnerable to attacks.**\n\n**Key Points:**\n\n- Trend Micro flags Nvidia's incomplete patch for a critical vulnerability.\n- The flaw allows potential container escape attacks and unauthorized access.\n- Organizations using Nvidia's toolkit are directly at risk, especially with default settings.\n- The patch doesn't properly enforce checks against race conditions, allowing exploitation.\n- A denial-of-service flaw has also been identified affecting Docker on Linux systems.\n\nTrend Micro researchers have flagged significant issues with Nvidia's patching of a critical vulnerability found in the Nvidia Container Toolkit, originally addressed last September. The vulnerability, identified as CVE-2024-0132, scored an alarming 9 out of 10 on the CVSS scale, categorizing it as high priority. However, Trend Micro's findings indicate that the patch is not fully effective, leaving enterprises exposed to dangerous container escape attacks. Such vulnerabilities enable hackers to execute arbitrary commands and access sensitive data, putting organizations' proprietary information at significant risk.\n\nThe security gap lies in the incomplete enforcement of checks that would typically prevent exploitation via the time-of-check to time-of-use (TOCTOU) race condition. This flaw allows a crafted container to maneuver past isolation barriers and manipulate host resources. The potential fallout from such exploitation includes theft of sensitive information, prolonged system downtime, and substantial operational disruptions. Organizations relying on the Nvidia Container Toolkit for their AI workloads and Docker environments must be aware of these risks, particularly those operating with default configurations or the newer features of the toolkit.\n\nAdditionally, alongside this vulnerability, Trend Micro has pointed out a related denial-of-service issue specifically affecting Docker configurations on Linux systems. Containers using specific mount options can lead to unchecked growth in the Linux mount table, creating a service disruption that can hinder remote access and overall operation. To mitigate these threats, Trend Micro advocates for stricter access controls and the disabling of unnecessary features within the Nvidia toolkit.\n\nHow are organizations adapting their security strategies in light of this Nvidia vulnerability?\n\n**Learn More:** [Security Week](https://www.securityweek.com/trend-micro-flags-incomplete-nvidia-patch-that-leaves-ai-containers-exposed/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1jzgsi1/nvidia_patch_incompleteness_poses_risks_in_ai/",
    "timestamp": "2025-04-15T02:22:37",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2023-27272"
    ],
    "cve_counts": {
      "CVE-2023-27272": 1
    },
    "title": "CVE Alert: CVE-2023-27272",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jzkeqs/cve_alert_cve202327272/",
    "timestamp": "2025-04-15T05:48:09",
    "article_text": "IBM Aspera Console 3.4.0 through 3.4.4 allows passwords to be reused when a new user logs into the system.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30406"
    ],
    "cve_counts": {
      "CVE-2025-30406": 1
    },
    "title": "CVE-2025-30406 - Critical Gladinet CentreStack & Triofox Vulnerability Exploited In The Wild",
    "text": "",
    "permalink": "/r/worldTechnology/comments/1jzmwwa/cve202530406_critical_gladinet_centrestack/",
    "timestamp": "2025-04-15T08:39:55",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30406"
    ],
    "cve_counts": {
      "CVE-2025-30406": 1
    },
    "title": "🚨 Just in: CVE-2025-30406 – Remote Code Execution via Hardcoded Crypto Keys in Gladinet CentreStack & Triofox",
    "text": "Gladinet’s platforms were found with a critical RCE vulnerability (CVSS 9.0) that has already been exploited in the wild using obfuscated PowerShell + DLL sideloading.\n\nHuntress confirmed **7 orgs compromised** so far. MeshCentral, Impacket, and lateral movement tactics spotted.  \nPatch now if you're on **Triofox ≤ v16.4.10317.56372**.  \n\\#Infosec #CVE202530406 #Sysadmin #ThreatIntel",
    "permalink": "/r/cybersecurityexams/comments/1jzmjro/just_in_cve202530406_remote_code_execution_via/",
    "timestamp": "2025-04-15T08:14:56",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3570"
    ],
    "cve_counts": {
      "CVE-2025-3570": 1
    },
    "title": "CVE Alert: CVE-2025-3570",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jznf1m/cve_alert_cve20253570/",
    "timestamp": "2025-04-15T09:16:24",
    "article_text": "A vulnerability was found in JamesZBL/code-projects db-hospital-drug 1.0. It has been classified as problematic. This affects the function Save of the file ContentController.java. The manipulation of the argument content leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30406"
    ],
    "cve_counts": {
      "CVE-2025-30406": 1
    },
    "title": "Gladinet flaw CVE-2025-30406 actively exploited in the wild",
    "text": "",
    "permalink": "/r/InfoSecNews/comments/1jzndlm/gladinet_flaw_cve202530406_actively_exploited_in/",
    "timestamp": "2025-04-15T09:13:23",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32056",
      "CVE-2025-32063"
    ],
    "cve_counts": {
      "CVE-2025-32056": 1,
      "CVE-2025-32063": 1
    },
    "title": "Gefährliche Sicherheitslücke: Hacker können Autos aus der Ferne steuern",
    "text": "# [Gefährliche Sicherheitslücke: Hacker können Autos aus der Ferne steuern](https://www.geblitzt.de/news/gefaehrliche-sicherheitsluecke-hacker-koennen-autos-aus-der-ferne-steuern/?utm_source=reddit&utm_medium=social_geblitzt&utm_campaign=post&utm_content=250415)\n\n# Sicherheitsforscher entdecken Schwachstelle in Fahrzeugsoftware\n\nWer permanent online ist, kann jederzeit Opfer eines Hackerangriffs werden. So lautet eine der Grundregeln des Internets, die natürlich auch Autos betrifft. Denn mittlerweile ist eine beachtliche Anzahl an Fahrzeugen dauerhaft vernetzt. Wie gravierend ein solcher Cyberangriff sich auf die Sicherheit von Leib und Leben auswirken kann, zeigen Forscher von PCAutomotive: Den Sicherheitsspezialisten ist es gelungen, einen Nissan verdeckt aus der Ferne zu kapern und zu steuern.\n\n[Golden Dayz \\/ shutterstock.com](https://preview.redd.it/ainwaentmzue1.jpg?width=1280&format=pjpg&auto=webp&s=d375e81c6c5b5d452d0a3535af0ae96385a6c3a7)\n\n# Vernetzung macht Autos verwundbarer\n\nGeht es nach einer Einschätzung von statista, wird im Jahr 2030 rund die Hälfte des europäischen Pkw-Bestands – etwa 255 Millionen Fahrzeuge – mit dem Internet verbunden sein. Blickt man weiter ins Jahr 2035, dürfte dieser Anteil in den USA bereits bei nahezu 100 Prozent der 290 Millionen Fahrzeuge liegen. Auch China zieht nach: Dort sollen bis dahin rund 72 Prozent der 350 Millionen Autos als Connected Cars unterwegs sein.\n\nDamit ist die Mehrheit der Fahrzeuge in diesen Ländern bereits vernetzt, Tendenz steigend. Dies bringt jedoch nicht nur Fortschritt und Komfort, sondern öffnet auch neue Angriffsmöglichkeiten für Kriminelle. Mit der zunehmenden Vernetzung der Fahrzeuge steigt das Risiko von Cyberangriffen, die von Datendiebstahl bis hin zur Manipulation von Fahrfunktionen reichen können.\n\n# Über Bluetooth eingehackt\n\nInwieweit sich tatsächlich sensible Fahrfunktionen kapern lassen, haben IT-Sicherheitsexperten von PCAutomotive auf der Hackerkonferenz Black Hat Asia 2025 demonstriert. Für ihre Präsentation verwendeten sie einen Nissan Leaf der zweiten Generation, Baujahr 2020.\n\nDabei erfolgte der Angriff durch ein Einfallstor in der Bluetooth-Schnittstelle des Elektroautos. Schwachstellen im Infotainmentsystem ermöglichten darüber hinaus eine Rechteerweiterung und schließlich einen verdeckten Fernzugriff über die Mobilfunkverbindung.\n\n# Dramatische Folgen für die Sicherheit der Insassen\n\nDie Folgen einer solchen Schwachstelle könnten kaum gravierender sein. Angreifer können den Standort des Fahrzeugs verfolgen und Inhalte des Infotainment-Bildschirms manipulieren oder mit Screenshots speichern. Gespräche können heimlich aufgezeichnet und sogar über den Lautsprecher des Autos wiedergegeben werden.\n\nEs kommt aber noch schlimmer: Auch physische Funktionen des Kraftfahrzeuges wie Türen, Scheibenwischer, Spiegel, Fenster und auch Leuchten können nach der Hacker-Übernahme sowohl aus dem Stand als auch während der Fahrt ferngesteuert werden.\n\nSogar die Lenkung des Fahrzeugs soll laut [netzwelt.de](http://netzwelt.de) aus der Ferne manipulierbar sein – der Albtraum eines jeden Autofahrers. Was einst nach düsterer Science-Fiction klang, ist heute eine reale und ernstzunehmende Bedrohung.\n\n# Cyberangriffe werden immer noch unterschätzt\n\nLaut der Präsentation von PCAutomotive sind die Cyberexperten auf insgesamt zehn Sicherheitslücken gestoßen. Diese sind mittlerweile unter den Codes PCA\\_NISSAN\\_009, PCA\\_NISSAN\\_012 und CVE-2025-32056 bis CVE-2025-32063 bekannt.\n\nDie Meldung an Nissan erfolgte bereits im August 2023. Dennoch hätten die Gegenmaßnahmen seitens des japanischen Autoherstellers viel Zeit in Anspruch genommen. Details will man bei Nissan aus Sicherheitsgründen nicht preisgeben.\n\nVielleicht aber auch aus Kalkül – denn die Hersteller tun noch immer zu wenig gegen Cyberangriffe. Immer wieder werden neue Schwachstellen bei verschiedenen Marken und Modellen bekannt. Allerdings sind nicht nur die Autobauer Schuld: Cybersicherheit kostet bares Geld und setzt man die Kundenbrille auf, handelt es sich um eine Verbesserung, die man schlicht nicht sehen kann.\n\n# Bußgeldvorwürfe stets über [Geblitzt.de](http://Geblitzt.de) prüfen lassen\n\nBei [Geblitzt.de](http://Geblitzt.de) arbeitet die CODUKA GmbH eng mit großen Anwaltskanzleien zusammen und ermöglicht es Betroffenen, sich gegen Bußgelder, Punkte und Fahrverbote zu wehren.\n\nRechtsschutzversicherungen übernehmen die Kosten eines vollständigen Leistungsspektrums unserer Partnerkanzleien. Ohne eine vorhandene Rechtsschutzversicherung übernimmt die CODUKA GmbH als Prozessfinanzierer die Kosten der Prüfung der Bußgeldvorwürfe und auch die Selbstbeteiligung Ihrer Rechtsschutzversicherung.\n\nTäglich erreicht das Geblitzt.de-Team eine Flut von Anfragen. 12 % der betreuten Fälle werden eingestellt, bei weiteren 35 % besteht die Möglichkeit einer Strafreduzierung.\n\nQuellen: [netzwelt.de](https://www.netzwelt.de/news/241087-gefahr-strassenverkehr-hacker-auto-fernsteuern.html), [adac.de](https://www.adac.de/rund-ums-fahrzeug/ausstattung-technik-zubehoer/autonomes-fahren/recht/autonomes-fahren-hacker-angriff/), [de.statista.com](https://de.statista.com/statistik/daten/studie/1246767/umfrage/anteil-vernetzter-pkw-am-bestand-in-europa/)",
    "permalink": "/r/u_Geblitztde/comments/1jzpzfq/gefährliche_sicherheitslücke_hacker_können_autos/",
    "timestamp": "2025-04-15T11:56:25",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-24859"
    ],
    "cve_counts": {
      "CVE-2025-24859": 5
    },
    "title": "Critical Apache Roller Insufficient Session Expiration on Password Change Vulnerability CVE-2025-24859",
    "text": "A session management vulnerability exists in Apache Roller before version 6.1.5 where active user sessions are not properly invalidated after password changes. When a user's password is changed, either by the user themselves or by an administrator, existing sessions remain active and usable. This allows continued access to the application through old sessions even after password changes, potentially enabling unauthorized access if credentials were compromised.\n\nThis issue affects Apache Roller versions up to and including 6.1.4.\n\nThe vulnerability is fixed in Apache Roller 6.1.5 by implementing centralized session management that properly invalidates all active sessions when passwords are changed or users are disabled.\n\nReferences:\n\n[https://cyberalerts.io/vulnerability/CVE-2025-24859](https://cyberalerts.io/vulnerability/CVE-2025-24859)\n\n[https://nvd.nist.gov/vuln/detail/CVE-2025-24859](https://nvd.nist.gov/vuln/detail/CVE-2025-24859)  \n[https://lists.apache.org/thread/vxv52vdr8nhtjlj6v02w43fdvo0cxw23](https://lists.apache.org/thread/vxv52vdr8nhtjlj6v02w43fdvo0cxw23)  \n[https://lists.apache.org/thread/4j906k16v21kdx8hk87gl7663sw7lg7f](https://lists.apache.org/thread/4j906k16v21kdx8hk87gl7663sw7lg7f)",
    "permalink": "/r/apache/comments/1jzs7kk/critical_apache_roller_insufficient_session/",
    "timestamp": "2025-04-15T13:42:50",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-29927"
    ],
    "cve_counts": {
      "CVE-2025-29927": 1
    },
    "title": "Next.js Middleware Auth Bypass (CVE-2025-29927) and Local File Read via XXE - HackDonalds Challenge",
    "text": "",
    "permalink": "/r/Intigriti/comments/1jzt9og/nextjs_middleware_auth_bypass_cve202529927_and/",
    "timestamp": "2025-04-15T14:28:09",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-2161"
    ],
    "cve_counts": {
      "CVE-2025-2161": 1
    },
    "title": "CVE Alert: CVE-2025-2161",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1jzsza6/cve_alert_cve20252161/",
    "timestamp": "2025-04-15T14:16:20",
    "article_text": "Pega Platform versions 7.2.1 to Infinity 24.2.1 are affected by an XSS issue with Mashup",
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-21762",
      "CVE-2022-42475",
      "CVE-2023-27997"
    ],
    "cve_counts": {
      "CVE-2022-42475": 1,
      "cve-2022-42475": 1,
      "CVE-2023-27997": 1,
      "cve-2023-27997": 1,
      "CVE-2024-21762": 1,
      "cve-2024-21762": 1
    },
    "title": "FortiOS 7.2.11 & 7.4.7",
    "text": "Due to [CVE-2022-42475](https://nvd.nist.gov/vuln/detail/cve-2022-42475?trk=article-ssr-frontend-pulse_little-text-block), [CVE-2023-27997,](https://nvd.nist.gov/vuln/detail/cve-2023-27997?trk=article-ssr-frontend-pulse_little-text-block) and [CVE-2024-21762](https://nvd.nist.gov/vuln/detail/cve-2024-21762?trk=article-ssr-frontend-pulse_little-text-block). Its recommended to upgrade to 7.2.11 and 7.4.7. Are those firmware stable? Or you guys recommend other version out of the vulnerability?",
    "permalink": "/r/fortinet/comments/1jzsu6r/fortios_7211_747/",
    "timestamp": "2025-04-15T14:10:17",
    "article_text": null,
    "comments": [
      {
        "score": 6,
        "text": "I manage 400 FortiGates and have 99% of them on 7.2.11 with no issues so far. Models range from 40F - 200E",
        "level": 0
      },
      {
        "score": 2,
        "text": "Thanks",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-0010"
    ],
    "cve_counts": {
      "CVE-2024-0010": 1
    },
    "title": "Mea Culpa",
    "text": "Yesterday I posted information about GlobalProtect related vulnerability. I was promptly given the beans by a contributor about disclosing this information, and I promptly gave some beans back. However, I now acknowledge that poster was correct -- I should not have created that post. Kudos to you, whoever you are. Leason learned.\n\nThat said, I would recommend reviewing CVE-2024-0010 and examining your devices in relation to this CVE. While the current issue is slightly different, there is impact beyond what the CVE describes. I'm sure we'll hear more about this from Palo soon.",
    "permalink": "/r/paloaltonetworks/comments/1jzwhrj/mea_culpa/",
    "timestamp": "2025-04-15T16:37:59",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "I'll also point out, I am a customer. I do no research or hacking. If I know about this, others (including miscreants) do as well. This is/was not a reason to create the post, just to emphasize a good intention poorly executed.",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-21204"
    ],
    "cve_counts": {
      "CVE-2025-21204": 1
    },
    "title": "Discussing the New inetpub Folder in Windows 11",
    "text": "\n**Windows users are urged to keep the inetpub folder.**  \n\nMicrosoft has confirmed that the newly introduced inetpub folder is a critical security feature rather than a rogue file. Users are advised against deleting it, even if it appears empty. This measure is part of a larger effort to bolster defenses against a significant vulnerability, CVE-2025-21204, that affects system permissions. Keeping this folder is essential to maintain security integrity.\n\nUsers have taken to discussions on how security measures like this can affect system administration practices and user experiences. Many share concerns about transparency in changes made by tech companies.\n\n- The inetpub folder is a part of security updates.\n\n- It prevents privilege escalation exploits.\n\n- Users without IIS are still impacted.\n\n[(View Details on PwnHub)](https://www.reddit.com/r/pwnhub/comments/1jzvuaf/microsoft_addresses_windows_11_users_concerns/)\n        ",
    "permalink": "/r/sysadmin/comments/1jzvvuk/discussing_the_new_inetpub_folder_in_windows_11/",
    "timestamp": "2025-04-15T16:13:19",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "This appears to be a bot.",
        "level": 0
      },
      {
        "score": 1,
        "text": "Posted under r/itcrowd as well... 😜",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-21204"
    ],
    "cve_counts": {
      "CVE-2025-21204": 2
    },
    "title": "Microsoft Addresses Windows 11 Users' Concerns About New inetpub Folder",
    "text": "\n**Microsoft has reassured Windows users that the newly appeared inetpub folder is an intentional security measure following recent updates.**\n\n**Key Points:**\n\n- The inetpub folder is created as part of a security update to mitigate a significant vulnerability.\n- Users should not delete the inetpub folder despite its empty appearance.\n- The folder enhances protection against privilege escalation exploits on Windows systems.\n\nWindows 10 and 11 users have recently noticed a seemingly empty directory called 'inetpub' appearing on their systems after installing Microsoft's April 2025 Patch Tuesday updates. While many users may see this folder as unnecessary and consider deleting it, Microsoft has explicitly warned against such action, clarifying that it plays a critical role in protecting systems from exploitation of a newly patched vulnerability, CVE-2025-21204. This vulnerability poses a serious risk as it allows unauthorized users to potentially gain system-level access, posing a significant threat to the integrity of a user's system.\n\nThe inetpub folder is typically associated with Microsoft's Internet Information Services (IIS) web server software. However, even users without IIS installed are affected by this change. The folder is created with specific read-only SYSTEM-level permissions, which enhances security measures against potential privilege escalation attempts. Microsoft reassures users that there is currently no evidence of active exploitation regarding CVE-2025-21204, but maintaining the folder's integrity is key to preventing future security risks. Thus, rather than being a cause for alarm, the folder signifies a proactive step by Microsoft in safeguarding Windows systems.\n\nHow do you feel about Microsoft creating this folder as a security measure without prior user notification?\n\n**Learn More:** [Cyber Security News](https://cybersecuritynews.com/microsoft-asks-windows-11-users/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1jzvuaf/microsoft_addresses_windows_11_users_concerns/",
    "timestamp": "2025-04-15T16:11:36",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-3567"
    ],
    "cve_counts": {
      "CVE-2025-3567": 1
    },
    "title": "CVE Alert: CVE-2025-3567",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k00g75/cve_alert_cve20253567/",
    "timestamp": "2025-04-15T19:16:22",
    "article_text": "A vulnerability, which was classified as problematic, was found in veal98 小牛肉 Echo 开源社区系统 4.2. Affected is the function preHandle of the file src/main/java/com/greate/community/controller/interceptor/LoginTicketInterceptor.java of the component Ticket Handler. The manipulation leads to improper authorization. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2023-6542"
    ],
    "cve_counts": {
      "CVE-2023-6542": 1
    },
    "title": "SAP Emarsys SDK for Android Sensitive Data Leak (CVE-2023-6542)",
    "text": "",
    "permalink": "/r/netsec/comments/1k0flpj/sap_emarsys_sdk_for_android_sensitive_data_leak/",
    "timestamp": "2025-04-16T08:41:45",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-27929"
    ],
    "cve_counts": {
      "CVE-2025-27929": 1
    },
    "title": "CVE Alert: CVE-2025-27929",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k0gxah/cve_alert_cve202527929/",
    "timestamp": "2025-04-16T10:16:22",
    "article_text": "Unauthenticated attackers can retrieve full list of users associated with arbitrary accounts.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2021-35587"
    ],
    "cve_counts": {
      "CVE-2021-35587": 1
    },
    "title": "Massive Oracle Cloud Breach: Threat Actor Sells 6M Records Exploited via Critical Vulnerability",
    "text": "On March 21, 2025, CloudSEK’s XVigil uncovered a high-severity security breach involving a threat actor operating under the alias “rose87168,” who is actively selling 6 million records exfiltrated from Oracle Cloud’s SSO and LDAP systems. The leaked data includes highly sensitive assets such as JKS files, encrypted SSO passwords, key files, and enterprise manager JPS keys, affecting over 140,000 tenants. \n\nThe attacker, who has been active since January 2025, is demanding payment for data removal and even incentivizing assistance in decrypting the stolen credentials. Initial analysis suggests the breach may have originated from a vulnerable Oracle login subdomain (login.\\[region\\].oraclecloud.com), possibly linked to CVE-2021-35587—a critical flaw in Oracle Fusion Middleware’s Access Manager.\n\nThe affected endpoint, last updated in 2014, underscores a lack of patch management and highlights broader concerns around supply chain vulnerabilities. Though the threat actor is new with no prior history, the sophistication of the attack, combined with extortion tactics and a potentially exploited zero-day.\n\nSource: [https://www.cloudsek.com/blog/the-biggest-supply-chain-hack-of-2025-6m-records-for-sale-exfiltrated-from-oracle-cloud-affecting-over-140k-tenants?utm\\_source=chatgpt.com](https://www.cloudsek.com/blog/the-biggest-supply-chain-hack-of-2025-6m-records-for-sale-exfiltrated-from-oracle-cloud-affecting-over-140k-tenants?utm_source=chatgpt.com)",
    "permalink": "/r/u_Sunitha_Sundar_5980/comments/1k0k8do/massive_oracle_cloud_breach_threat_actor_sells_6m/",
    "timestamp": "2025-04-16T13:19:09",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2014-0160",
      "CVE-2017-5754"
    ],
    "cve_counts": {
      "CVE-2014-0160": 2,
      "CVE-2017-5754": 2
    },
    "title": "Homeland Security funding for CVE program expires",
    "text": ">US government funding for the world's CVE program – the centralized Common Vulnerabilities and Exposures database of product security flaws – ends Wednesday.\n\n>The 25-year-old CVE program plays a huge role in vulnerability management. It is responsible overseeing the assignment and organizing of unique CVE ID numbers, such as [CVE-2014-0160](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160) and [CVE-2017-5754](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754), for specific vulnerabilities, in this case OpenSSL's [Heartbleed](https://www.theregister.com/2014/04/09/heartbleed_explained/) and Intel's [Meltdown](https://www.theregister.com/2018/01/02/intel_cpu_design_flaw/), so that when referring to particular flaws and patches, everyone is agreed on exactly what we're all talking about.\n\n>It is used by companies big and small, developers, researchers, the public sector, and more as the primary system for identifying and squashing bugs. When multiple people find the same hole, CVEs are useful for ensuring everyone is working toward that one specific issue.\n\n>",
    "permalink": "/r/DeFranco/comments/1k0jqgm/homeland_security_funding_for_cve_program_expires/",
    "timestamp": "2025-04-16T12:55:53",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3155"
    ],
    "cve_counts": {
      "cve-2025-3155": 1
    },
    "title": "It's time to retire Yelp",
    "text": "GNOME's [Help](https://gitlab.gnome.org/GNOME/yelp) app has a lot going against it\n\n* A [dangerous critical vulnerability](https://blogs.gnome.org/mcatanzaro/2025/04/15/dangerous-arbitrary-file-read-vulnerability-in-yelp-cve-2025-3155/) that hasn't been patched in months\n* Hasn't migrated to Gtk4\n* Doesn't conform to the Human Interface Guidelines\n* And (most importantly) nobody uses it since we have Google and [Biblioteca](https://apps.gnome.org/Biblioteca/)\n\nCan we go ahead and retire it from GNOME's core apps?",
    "permalink": "/r/gnome/comments/1k0l7cl/its_time_to_retire_yelp/",
    "timestamp": "2025-04-16T14:03:16",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-24054": 1
    },
    "title": "CVE-2025-24054, NTLM Exploit in the Wild - Check Point Research",
    "text": "",
    "permalink": "/r/SecOpsDaily/comments/1k0m6wf/cve202524054_ntlm_exploit_in_the_wild_check_point/",
    "timestamp": "2025-04-16T14:45:45",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-27561"
    ],
    "cve_counts": {
      "CVE-2025-27561": 1
    },
    "title": "CVE Alert: CVE-2025-27561",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k0mxgy/cve_alert_cve202527561/",
    "timestamp": "2025-04-16T15:16:20",
    "article_text": "Unauthenticated attackers can rename “rooms” of arbitrary users.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-21204",
      "CVE-2025-0282",
      "CVE-2025-22457",
      "CVE-2025-30406",
      "CVE-2025-27840",
      "CVE-2025-24859",
      "CVE-2025-24994",
      "CVE-2024-26170",
      "CVE-2025-24076",
      "CVE-2024-50264"
    ],
    "cve_counts": {
      "CVE-2025-27840": 1,
      "CVE-2024-50264": 1,
      "CVE-2025-24076": 1,
      "CVE-2025-21204": 1,
      "CVE-2025-30406": 1,
      "CVE-2025-0282": 1,
      "CVE-2024-26170": 1,
      "CVE-2025-24994": 1,
      "CVE-2025-24859": 1,
      "CVE-2025-22457": 1
    },
    "title": "🔥 Top 10 Trending CVEs (16/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. CVE-2025-27840**\n\n- 📝 A potential security vulnerability affects Espressif ESP32 chips, enabling undocumented HCI commands, including 0xFC02 (Write memory). The severity is moderate (CVSS 6.8), and exploitation requires high attack complexity with no user interaction needed (AV:P/AC:H). No known instances of exploitation in the wild have been reported as of yet.\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**2. CVE-2024-50264**\n\n- 📝 In the Linux Kernel, a Use-After-Free vulnerability exists within vsock/virtio. During loopback communication, a dangling pointer can be created in vsk->trans, potentially leading to memory corruption when using versions specified in the description. The severity is high due to potential code execution and data disclosure. No known exploitation has been observed in the wild.\n\n- 📅 **Published:** 19/11/2024\n- 📈 **CVSS:** 7.8\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**3. CVE-2025-24076**\n\n- 📝 A locally-exploitable privilege escalation vulnerability exists within Windows Cross Device Service. This flaw could allow an attacker with authorized access to elevate their privileges locally. No known exploitation in the wild has been reported at this time. Ensure affected systems are up-to-date.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 7.3\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H\n\n---\n\n**4. CVE-2025-21204**\n\n- 📝 A local privilege escalation vulnerability exists in Windows Update Stack, permitting authorized attackers to elevate privileges by leveraging improper link resolution prior to file access. Verify affected versions align with the description for potential mitigation or patching actions.\n\n- 📅 **Published:** 08/04/2025\n- 📈 **CVSS:** 7.8\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**5. CVE-2025-30406**\n\n- 📝 Unpatched Gladinet CentreStack versions prior to 16.4.10315.56368 contain a server-side deserialization vulnerability, enabling remote code execution. Known to have been exploited in the wild since March 2025. The hardcoded machineKey in portal\\web.config is the attack vector. Administrators are advised to manually delete this key and apply updates.\n\n- 📅 **Published:** 3/4/2025\n- 📈 **CVSS:** 9\n- 🛡️ **CISA KEV:** Yes\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**6. CVE-2025-0282**\n\n- 📝 A critical, remotely exploitable stack-based buffer overflow vulnerability exists in Ivanti Connect Secure before 22.7R2.5, Ivanti Policy Secure before 22.7R1.2, and Ivanti Neurons for ZTA gateways before 22.7R2.3, enabling unauthenticated attackers to execute arbitrary code. This vulnerability has been exploited in the wild according to CISA KEV. Immediate patching or mitigation measures are strongly advised.\n\n- 📅 **Published:** 08/01/2025\n- 📈 **CVSS:** 9\n- 🛡️ **CISA KEV:** Yes\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**7. CVE-2024-26170**\n\n- 📝 A Windows CimFS EoP vulnerability exists, allowing local attackers to elevate privileges. This issue is remotely exploitable without authentication and may result in high impact on confidentiality, integrity, and availability. Verify if affected versions match those listed in the description.\n\n- 📅 **Published:** 12/03/2024\n- 📈 **CVSS:** 7.8\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**8. CVE-2025-24994**\n\n- 📝 A locally-exploitable privilege escalation vulnerability exists in Windows Cross Device Service, enabling an authorized attacker to elevate privileges. Verify affected versions match those listed in the description for potential security impact.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 7.3\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H\n\n---\n\n**9. CVE-2025-24859**\n\n- 📝 I've identified a critical session management vulnerability in Apache Roller before version 6.1.5, specifically affecting versions up to and including 6.1.4. After password changes, active user sessions remain intact, allowing potential unauthorized access through old sessions. Implement centralized session management to mitigate this risk by updating to Apache Roller 6.1.5 or higher.\n\n- 📅 **Published:** 14/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X\n\n---\n\n**10. CVE-2025-22457**\n\n- 📝 A critical, remotely exploitable stack-based buffer overflow vulnerability (stack-buffer-overflow) exists in Ivanti Connect Secure before 22.7R2.6, Ivanti Policy Secure before 22.7R1.4, and Ivanti ZTA Gateways before 22.8R2.2. This flaw allows unauthenticated attackers to execute arbitrary code (Remote Code Execution). Notably, this vulnerability has been observed in active exploitation by threat actors. Immediate patching is strongly advised.\n\n- 📅 **Published:** 3/4/2025\n- 📈 **CVSS:** 9\n- 🛡️ **CISA KEV:** Yes\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\nLet me know if you're tracking any of these or if something flew under the radar 👀",
    "permalink": "/r/CVEWatch/comments/1k0pflo/top_10_trending_cves_16042025/",
    "timestamp": "2025-04-16T17:00:12",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30100"
    ],
    "cve_counts": {
      "CVE-2025-30100": 2
    },
    "title": "Critical Security Flaw in Dell Alienware Command Center Exposes Users to Privilege Escalation",
    "text": "\n**Dell has issued a security update to patch a serious vulnerability in Alienware Command Center that could allow unauthorized users to gain elevated access on affected systems.**\n\n**Key Points:**\n\n- Vulnerability CVE-2025-30100 affects all versions of Alienware Command Center prior to 6.7.37.0.\n- Attackers with local access can exploit this flaw potentially leading to severe security compromises.\n- Users are urged to update immediately to the latest version to mitigate risks.\n\nDell Technologies has released a critical update for its Alienware Command Center software due to a significant security vulnerability tracked as CVE-2025-30100. This weakness in the software could allow a low-privileged attacker with local access to exploit the system, resulting in elevated privileges that might enable them to manipulate sensitive data or disrupt operations. With a CVSS score of 6.7, this vulnerability indicates a medium-severity issue that should be taken seriously by all users of the software, especially those on Dell's gaming platforms. Since the Alienware Command Center plays an essential role in system optimization and customization for gamers, the implications of this vulnerability are far-reaching. Successful exploits could lead to unauthorized access to personal data or system disruption, raising serious concerns among users about the integrity of their systems.\n\nResearcher “bugzzzhunter,” who discovered this vulnerability, pointed out that while the exploit does require specific conditions to be met—such as user interaction and low privileges—the potential consequences are significant. Privilege escalation vulnerabilities are particularly alarming because they allow an attacker to gain a more substantial foothold in a compromised system, thus escalating their capabilities. With a history of previous vulnerabilities in Alienware's software, Dell's consistent updating and communication practices are crucial for maintaining user trust. However, given that this vulnerability has now been publicly disclosed, users need to act quickly to apply the necessary updates and protect their systems from potential exploitation.\n\nHave you updated your Alienware Command Center software since the vulnerability disclosure?\n\n**Learn More:** [Cyber Security News](https://cybersecuritynews.com/dell-alienware-command-center-vulnerability/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k0ow2s/critical_security_flaw_in_dell_alienware_command/",
    "timestamp": "2025-04-16T16:38:01",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-24054": 2
    },
    "title": "Cybercriminals Exploit Critical NTLM Spoofing Vulnerability in Windows Systems",
    "text": "\n**Hackers are actively taking advantage of a serious vulnerability in Windows systems, CVE-2025-24054, to leak sensitive authentication data.**\n\n**Key Points:**\n\n- Vulnerability facilitates NTLM hash leakage through spoofing techniques.\n- Attackers can escalate privileges and move laterally within networks.\n- Exploitation requires minimal user interaction, increasing risk.\n- Recent campaigns target government and private institutions in Eastern Europe.\n\nCybercriminals are currently exploiting a severe vulnerability identified as CVE-2025-24054, which relates to the NTLM authentication protocol used within Windows systems. This vulnerability allows attackers to manipulate file path handling in a way that triggers SMB authentication requests, revealing user NTLM hashes through unsuspecting file operations. What makes this exploit particularly concerning is its ability to occur with minimal user interaction, such as simply unzipping a ZIP file that contains a malicious .library-ms file. As soon as the file is extracted, the user's authentication data can be leaked, paving the way for further exploitation by the attackers.\n\nRecent reports indicate that threat actors began utilizing this vulnerability shortly after Microsoft's attempted patch on March 11, 2025. Campaigns observed in late March specifically targeted institutions in Poland and Romania, showcasing the vulnerability's appeal to malicious groups. By embedding harmful files in spear-phishing emails, attackers prompted unwitting users to execute the harmful ZIP archives, triggering the vulnerability and exposing their NTLM hashes. The attackers were then able to leverage these hashes for lateral movements within networks, thereby gaining unauthorized access and potentially escalating privileges, all while evading detection.\n\nWhat measures do you think organizations should prioritize in response to such rapidly exploited vulnerabilities?\n\n**Learn More:** [Cyber Security News](https://cybersecuritynews.com/hackers-exploiting-ntlm-spoofing-vulnerability/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k0ov7f/cybercriminals_exploit_critical_ntlm_spoofing/",
    "timestamp": "2025-04-16T16:37:02",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-24859"
    ],
    "cve_counts": {
      "CVE-2025-24859": 2
    },
    "title": "Critical Vulnerability Exposes Apache Roller Users to Persistent Threats",
    "text": "\n**A newly identified vulnerability in Apache Roller could allow attackers to retain access to user accounts even after password changes.**\n\n**Key Points:**\n\n- Vulnerability allows attackers to reuse old sessions after passwords are changed.\n- CVE-2025-24859 has a maximum severity score of 10/10, highlighting its critical nature.\n- All Roller versions prior to 6.1.5 are affected by this security flaw.\n- Apache has issued a patch that includes improved session management to mitigate the risk.\n\nA critical cybersecurity flaw, tracked as CVE-2025-24859, has been discovered in Apache Roller, an open-source Java-based blog server. This vulnerability allows attackers to maintain access via active sessions even after users have changed their passwords. This flaw affects all versions up to 6.1.4, posing severe risks for user account integrity and application security. With a CVSS score of 10/10, the severity of this vulnerability cannot be overstated, as it could enable unauthorized access to sensitive information and continued exploitation of accounts by malicious actors.\n\nApache has recently addressed this issue through the release of version 6.1.5, which implements improvements in session management. The update ensures that all active sessions are properly invalidated when a password is changed or an account is disabled. This response is crucial because it not only addresses the current vulnerability but also enhances the overall security framework of the platform. Such proactive measures are necessary to protect users from ongoing threats, especially in light of recent statistics showing an increase in attacks targeting session management flaws across various applications.\n\nWhat steps do you think organizations should take to enhance security against such vulnerabilities?\n\n**Learn More:** [Security Week](https://www.securityweek.com/critical-vulnerability-found-in-apache-roller-blog-server/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k0omjb/critical_vulnerability_exposes_apache_roller/",
    "timestamp": "2025-04-16T16:27:03",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-53197",
      "CVE-2024-53150"
    ],
    "cve_counts": {
      "cve-2024-53150": 1,
      "cve-2024-53197": 1
    },
    "title": "M6P | C431(EU) | NEW PATCH",
    "text": "[9.0.0.164](http://9.0.0.164)\n\ncve-2024-53150 y cve-2024-53197 are NOT patched.\n\nhttps://preview.redd.it/pw4vwhnw38ve1.png?width=1255&format=png&auto=webp&s=a0c36d951623167f9e3e6912e9bb9f12ccfa28f6\n\n  \n",
    "permalink": "/r/Honor/comments/1k0oj98/m6p_c431eu_new_patch/",
    "timestamp": "2025-04-16T16:23:18",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "Dang no ai zoom",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-27840"
    ],
    "cve_counts": {
      "CVE-2025-27840": 1
    },
    "title": "Hardware Can’t Be Trusted — So We Built Around It",
    "text": "A recent vulnerability (CVE-2025-27840) affecting the popular ESP32 microcontroller is exposing Bitcoin hardware wallets to key theft. The flaw includes:\n\n• Exploitable firmware/module updates\n• Weak RNG entropy → brute-forceable keypairs\n• Remote signature injection & transaction hijacking\n\nThis isn’t just about one chip — it’s about a fundamental design flaw:\n🔹 If trust is rooted in hardware, the system is only as strong as its weakest microcontroller.\n\nWhat We Did Instead\nWe’ve been working on an architecture that treats trust as behavior, not assumption.\n\nNo reliance on global consensus or secure hardware. Instead:\n\n• Agents validate state locally\n• Trust scores are based on entropy quality, signature patterns, and behavior\n• Adaptive PoW rejects anomalies — even if signed\n• Entropy audits detect weak randomness in real time\n• Devices that act “out of spec” are automatically isolated or demoted\n\nIf a key becomes guessable or spoofed, the system doesn’t alert — it acts.\n\nBig Picture:\nCryptography isn’t just math.\nIt’s entropy. It’s behavior. It’s architecture.\n\nThe next evolution in blockchain security won't come from stronger chips.\nIt’ll come from smarter systems that expect them to fail.\n\nLet me know if anyone’s working on similar agent-based or entropy-scoring models. Always curious to compare architectures.\n\n",
    "permalink": "/r/CryptoTechnology/comments/1k0scrw/hardware_cant_be_trusted_so_we_built_around_it/",
    "timestamp": "2025-04-16T18:56:54",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-26870"
    ],
    "cve_counts": {
      "CVE-2025-26870": 1
    },
    "title": "CVE Alert: CVE-2025-26870",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k0ua4o/cve_alert_cve202526870/",
    "timestamp": "2025-04-16T20:16:24",
    "article_text": "Improper Neutralization of Input During Web Page Generation (‘Cross-site Scripting’) vulnerability in NotFound JetEngine allows DOM-Based XSS. This issue affects JetEngine: from n/a through 3.6.4.1.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-12345"
    ],
    "cve_counts": {
      "CVE-2025-12345": 1
    },
    "title": "CVE program's funding crisis: Implications and strategic response",
    "text": "*Today, the cybersecurity community faced a critical juncture as the U.S. government's contract with MITRE Corporation to develop, operate and modernize the Common Vulnerabilities and Exposures (CVE) program, as well as related efforts like CWE, was set to expire.*\n\n[Adam Khan, April 16, 2025](https://blog.barracuda.com/2025/04/16/cve-program-funding-crisis)\n\nToday, the cybersecurity community faced a critical juncture as the U.S. government's contract with MITRE Corporation to develop, operate and modernize the [Common Vulnerabilities and Exposures (CVE) program](https://cve.mitre.org/), as well as related efforts like CWE, was set to expire.\n\nMITRE warned of \"multiple impacts to CVE, including deterioration of national vulnerability databases and advisories, tool vendors, incident response operations, and all manner of critical infrastructure.\"\n\nThis development threatened the continuity of a foundational element in global cybersecurity infrastructure. In a last-minute intervention, the Cybersecurity and Infrastructure Security Agency (CISA) extended funding and awarded an 11-month bridge contract to ensure there would be no lapse in CVE services.\n\nhttps://preview.redd.it/lbyeumybt9ve1.png?width=375&format=png&auto=webp&s=eb7f0728ef1ca829568cdf3a1255c5d8ebce97e7\n\n# Understanding the CVE Program\n\nThe CVE program, established in 1999 and managed by MITRE, provides a standardized system for identifying and cataloging publicly known cybersecurity vulnerabilities. Each vulnerability is assigned a unique identifier (e.g., CVE-2025-12345), facilitating consistent communication among security professionals, vendors and organizations worldwide.\n\nCVE records are categorized based on the type of vulnerability, affected software or hardware, and potential impact. These records typically include a brief description, references to public advisories or patches, and severity ratings, when available.\n\nThe lifecycle of a CVE follows a structured process:\n\n1. **Discovery** – A researcher, vendor or organization identifies a potential security flaw.\n2. **Submission** – The issue is reported to a CVE Numbering Authority (CNA), which validates and assigns a CVE ID.\n3. **Disclosure** – After validation, the vulnerability is publicly disclosed either by the discoverer or the CNA, depending on coordination.\n4. **Publication** – The CVE entry is published to the CVE List and made available to the community for integration into tools and databases.\n5. **Ongoing Maintenance** – MITRE and CNAs monitor for corrections, updates and additional reference material to keep the records accurate and useful.\n\nThe CVE program serves as a backbone for security tools and frameworks such as the National Vulnerability Database (NVD), which augments CVE records with CVSS scores and metadata, and the Common Weakness Enumeration (CWE), which categorizes the underlying flaw types.\n\nBy offering a centralized, transparent, and community-driven system, the CVE program supports timely vulnerability management and helps coordinate global response efforts.\n\n# Importance of the CVE program\n\nThe CVE program is foundational to global cybersecurity efforts for several reasons:\n\n* **Standardization:** It offers a common language for describing vulnerabilities, enabling effective collaboration across different organizations and sectors.​\n* **Integration:** Many security tools and processes rely on CVE identifiers to function correctly, including vulnerability scanners, patch management systems and threat intelligence platforms.\n* **Coordination:** The program supports coordinated vulnerability disclosure, allowing vendors and researchers to manage and communicate about security issues efficiently.​\n\nWithout the CVE system, the cybersecurity community would face challenges in tracking, prioritizing and mitigating vulnerabilities, leading to increased risks and potential exploitation by threat actors.\n\n# Implications for the cybersecurity industry\n\nThe potential lapse in CVE program funding raised several concerns:​\n\n* **Operational disruption:** A halt in CVE assignments could disrupt security vendors, security teams such as Incident responders and many others, as organizations would lack standardized identifiers for new vulnerabilities.​\n* **Increased risk:** Delayed vulnerability identification and remediation efforts could expose systems to prolonged periods of risk.​\n* **Fragmentation:** In the absence of a centralized system, disparate methods for tracking vulnerabilities might emerge, leading to inconsistencies and confusion.​\n\nThese challenges underscore the critical role of the CVE program in maintaining cybersecurity resilience across industries and national infrastructures.\n\n# Strategic response and recommendations\n\nTo ensure the sustainability and effectiveness of the CVE program, the following measures are recommended:\n\n**1. Diversify funding sources**\n\nEngage stakeholders from the private sector, international partners and non-profit organizations to contribute to the program's funding, reducing reliance on a single government entity.​\n\n**2. Establish independent governance**\n\nThe formation of the CVE Foundation aims to provide a neutral, community-driven governance structure, enhancing the program's resilience and global trust.​\n\n**3. Enhance transparency**\n\nRegular communication about the program's status, funding and strategic direction can build confidence among users and contributors.​\n\n**4. Invest in automation**\n\nLeveraging automation and artificial intelligence can improve the efficiency of vulnerability identification and management processes.​\n\n**5. Strengthen international collaboration**\n\nFoster partnerships with international cybersecurity organizations to ensure a unified approach to vulnerability management and to share best practices.\n\n# European Union's proactive measures\n\nIn response to the evolving cybersecurity landscape, the European Union Agency for Cybersecurity (ENISA) has launched the European Vulnerability Database ([EUVD](https://euvd.enisa.europa.eu/)). This initiative embraces a multi-stakeholder approach by collecting publicly available vulnerability information from multiple sources, including Computer Security Incident Response Teams (CSIRTs), vendors and existing databases. The EUVD aims to enhance transparency and efficiency in vulnerability management across the EU.\n\n# Ensuring resilience and sustainability moving forward\n\nThe recent funding crisis of the CVE program highlights the fragility of essential cybersecurity infrastructures. While immediate disruptions have been averted, it is imperative for the global cybersecurity community to take proactive steps to ensure the resilience and sustainability of vulnerability management systems. Collaborative efforts, diversified funding and international cooperation will be key to safeguarding our digital ecosystems.\n\n**References:**\n\n* [MITRE Signals Potential CVE Program Deterioration as US Gov Funding Expires](https://www.securityweek.com/mitre-signals-potential-cve-program-deterioration-as-us-gov-funding-expires/)\n* [CISA Extends Funding to Ensure No Lapse in Critical CVE Services](https://www.bleepingcomputer.com/news/security/cisa-extends-funding-to-ensure-no-lapse-in-critical-cve-services/)\n* [Funding Expires for Key Cyber Vulnerability Database](https://krebsonsecurity.com/2025/04/funding-expires-for-key-cyber-vulnerability-database/)\n* [CVE Program Funding Expires—What It Means And What To Do Next](https://www.forbes.com/sites/kateoflahertyuk/2025/04/16/cve-program-funding-cut-what-it-means-and-what-to-do-next/)\n* [Another Step Forward Towards Responsible Vulnerability Disclosure in Europe](https://www.enisa.europa.eu/news/another-step-forward-towards-responsible-vulnerability-disclosure-in-europe)\n* [ENISA Vulnerability Disclosure](https://www.enisa.europa.eu/topics/vulnerability-disclosure)\n\nhttps://preview.redd.it/1b9m9b9wt9ve1.jpg?width=1200&format=pjpg&auto=webp&s=7f84681c373eba979a9445cd792f306028c76ea3\n\n[This article originally appeared on the Barracuda Blog.](https://blog.barracuda.com/2025/04/16/cve-program-funding-crisis)\n\n[Adam Khan](https://blog.barracuda.com/author/adam-khan)\n\nAdam Khan is the VP, Global Security Operations at Barracuda MSP. He currently leads a Global Security Team which consist of highly skilled Blue, Purple, and Red Team members. He previously worked over 20 years for companies such as [Priceline.com](http://priceline.com/), [BarnesandNoble.com](http://barnesandnoble.com/), and Scholastic. Adam's experience is focused on application/infrastructure automation and security. He is passionate about protecting SMBs from cyberattacks, which is the heart of American innovation.\n\n",
    "permalink": "/r/BarracudaNetworks/comments/1k0x1z7/cve_programs_funding_crisis_implications_and/",
    "timestamp": "2025-04-16T22:14:26",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2023-48795",
      "CVE-2018-15473"
    ],
    "cve_counts": {
      "CVE-2018-15473": 1,
      "CVE-2023-48795": 1
    },
    "title": "SSH Hardening & Offensive Mastery - Libro técnico con enfoque práctico",
    "text": " Hola a todos,\n\nDesde el grupo **DSDSec** queremos compartir con la comunidad un libro técnico que hemos publicado recientemente: **\"SSH Hardening & Offensive Mastery\"**. Se trata de un recurso gratuito centrado exclusivamente en la seguridad del protocolo SSH, con un enfoque tanto **defensivo como ofensivo**, acompañado de múltiples laboratorios prácticos.\n\n\n\n[Portada de libro: SSH Hardening & Offensive Mastery](https://preview.redd.it/xwy0jxjpt9ve1.png?width=250&format=png&auto=webp&s=3e8fa9f45653e632b9fe48996f47e0709928da27)\n\nEl libro está orientado a sysadmins, equipos red/blue, amantes de la ciberseguridad y cualquier persona interesada en fortalecer sus conocimientos técnicos, desde niveles iniciales hasta avanzados.\n\n# Algunos de los temas tratados:\n\n* Configuraciones seguras y buenas prácticas\n* Implementación de 2FA sobre SSH\n* Fail2Ban y Suricata (IDS/IPS)\n* Tipos de túneles SSH (local, remoto, dinámico, UDP)\n* Evasión de restricciones y filtrado de red\n* SSH agent hijacking y secuestro de sesiones\n* Propagación de malware a través de túneles dinámicos (con Metasploit y BlueKeep)\n* Análisis y mitigación de vulnerabilidades como **CVE-2018-15473** y **Terrapin (CVE-2023-48795)**\n* Abuso de variables de entorno\n* Desarrollo de herramientas personalizadas en **Tcl/Expect** y **Perl**\n\nEl libro incluye laboratorios detallados, explicaciones técnicas paso a paso.\n\n📘 **Descarga de PDF**:  \n[https://dsdsec.com/wp-content/uploads/2025/04/SSH-Hardening-and-Offensive-Mastery.pdf](https://dsdsec.com/wp-content/uploads/2025/04/SSH-Hardening-and-Offensive-Mastery.pdf)\n\n🌐 **Más información sobre la publicación**:  \n[https://dsdsec.com/publications/](https://dsdsec.com/publications/)\n\n Esperamos que os guste y resulte útil. Cualquier comentario o feedback es más que bienvenido.",
    "permalink": "/r/ciberseguridad/comments/1k0x15b/ssh_hardening_offensive_mastery_libro_técnico_con/",
    "timestamp": "2025-04-16T22:13:24",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-26746"
    ],
    "cve_counts": {
      "CVE-2025-26746": 1
    },
    "title": "CVE Alert: CVE-2025-26746",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k0zmxh/cve_alert_cve202526746/",
    "timestamp": "2025-04-17T00:16:23",
    "article_text": "Improper Neutralization of Input During Web Page Generation (‘Cross-site Scripting’) vulnerability in NotFound Advanced Custom Fields: Link Picker Field allows Reflected XSS. This issue affects Advanced Custom Fields: Link Picker Field: from n/a through 1.2.8.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-27840"
    ],
    "cve_counts": {
      "cve-2025-27840": 2
    },
    "title": "Cold wallets with ESP32 chip, are on high alert after a new critical vulnerability error",
    "text": "This does not concern Ledger wallets, but interesting information:  \n  \n\"Wallets that use the ESP32 chip, including Blockstream’s Jade wallet, are on high alert after a new critical vulnerability error\"  \n  \nLinks:\n\n[https://securityonline.info/cve-2025-27840-how-a-tiny-esp32-chip-could-crack-open-bitcoin-wallets-worldwide/](https://securityonline.info/cve-2025-27840-how-a-tiny-esp32-chip-could-crack-open-bitcoin-wallets-worldwide/)\n\n[https://protos.com/chinese-chip-used-in-bitcoin-wallets-is-putting-traders-at-risk/](https://protos.com/chinese-chip-used-in-bitcoin-wallets-is-putting-traders-at-risk/)\n\n(hoping Ledger never has such a flaw in the future)",
    "permalink": "/r/ledgerwallet/comments/1k14nk9/cold_wallets_with_esp32_chip_are_on_high_alert/",
    "timestamp": "2025-04-17T04:46:47",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "Scammers continuously target the Ledger subreddit. Ledger Support will never send you private messages or [call you on the phone](https://support.ledger.com/article/15839986186269-zd). Never share your 24-word secret recovery phrase with anyone or enter it anywhere, even if it appears to be from Ledger. Keep your 24-word secret recovery phrase only as a physical paper or metal backup, never as a digital copy. [Learn more about phishing attacks](https://reddit.com/r/ledgerwallet/comments/ck6o44/be_careful_phishing_attacks_in_progress/). \n\nExperiencing battery or device issues? [Check our trouble shooting guide](https://support.ledger.com/article/4409233434641-zd).If problems persist, visit the [My Order page](https://my-order.ledger.com/) for replacement or refund options. \n\nReceived an unknown NFT? Don’t interact with it. [Learn more about handling unknown NFTs](https://support.ledger.com/article/6857182078749-zd).\n\nFor other technical issues or bugs, see our [known issues page](https://support.ledger.com/article/15158192560157-zd) for up-to-date information and workarounds. \n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/ledgerwallet) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-31201",
      "CVE-2025-31200"
    ],
    "cve_counts": {
      "CVE-2025-31200": 1,
      "CVE-2025-31201": 1
    },
    "title": "iOS 18.4.1 est disponible et vous devriez vous dépêcher de l’installer",
    "text": "* Apple a publié la mise à jour iOS 18.4.1 pour corriger un bug de connexion à CarPlay et deux failles de sécurité majeures, qui étaient activement exploitées par des pirates.\n* La première faille (CVE-2025-31200) touchait CoreAudio et permettait à des attaquants d'exécuter du code arbitraire à distance via un fichier audio malveillant.\n* La seconde faille (CVE-2025-31201) concernait RPAC, un module de sécurité des puces d'Apple, permettant à un pirate d'accéder à la mémoire de l'appareil et de contourner les protections de sécurité.",
    "permalink": "/r/actutech/comments/1k16qiv/ios_1841_est_disponible_et_vous_devriez_vous/",
    "timestamp": "2025-04-17T07:07:41",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-20150"
    ],
    "cve_counts": {
      "CVE-2025-20150": 1
    },
    "title": "Cisco Nexus Dashboard LDAP Username Enumeration Vulnerability (CVE-2025-20150)",
    "text": "",
    "permalink": "/r/systemtek/comments/1k16yqw/cisco_nexus_dashboard_ldap_username_enumeration/",
    "timestamp": "2025-04-17T07:24:16",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-31201"
    ],
    "cve_counts": {
      "CVE-2025-31201": 1
    },
    "title": "Is anything known about CVE-2025-31201?",
    "text": "Apple speaks of an extremely sophisticated attack.\n\nhttps://support.apple.com/en-us/122282\n\nImpact: An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS",
    "permalink": "/r/jailbreak/comments/1k18x2l/is_anything_known_about_cve202531201/",
    "timestamp": "2025-04-17T09:50:27",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "they patched it by removing the vulnerable code in IOS 18.4.1\n\n[https://www.cve.org/CVERecord?id=CVE-2025-31201](https://www.cve.org/CVERecord?id=CVE-2025-31201)",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-29306"
    ],
    "cve_counts": {
      "CVE-2025-29306": 1
    },
    "title": "POC - CVE-2025-29306 FOXCMS /images/index.html Code Execution Vulnerability",
    "text": "",
    "permalink": "/r/ExploitDev/comments/1k18u26/poc_cve202529306_foxcms_imagesindexhtml_code/",
    "timestamp": "2025-04-17T09:44:00",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32791"
    ],
    "cve_counts": {
      "CVE-2025-32791": 1
    },
    "title": "CVE Alert: CVE-2025-32791",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k19adj/cve_alert_cve202532791/",
    "timestamp": "2025-04-17T10:16:23",
    "article_text": "The Backstage Scaffolder plugin houses types and utilities for building scaffolder-related modules. A vulnerability in the Backstage permission plugin backend allows callers to extract some information about the conditional decisions returned by the permission policy installed in the permission backend. If the permission system is not in use or if the installed permission policy does not use conditional decisions, there is no impact. This issue has been patched in version 0.6.0 of the permissions backend. A workaround includes having administrators of the permission policies ensure that they are crafted in such a way that conditional decisions do not contain any sensitive information.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-31201"
    ],
    "cve_counts": {
      "CVE-2025-31201": 1
    },
    "title": "Are there unused chunks of code in macOS?  Here's why I ask…",
    "text": "If you read Apple's article:\n[About the security content of macOS Sequoia 15.4.1](https://support.apple.com/en-us/122400)\n\nYou'll see this:\n\n> RPAC \\\n> \\\n> Available for: macOS Sequoia \\\n> \\\n> Impact: An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS. \\\n> \\\n> Description: **This issue was addressed by removing the vulnerable code.** \\\n> \\\n> CVE-2025-31201: Apple\n\n**Just what the heck did that removed code do?**\n\nIf the vulnerable code was part of some feature, them removing it would remove that feature. But the release notes made no mention of removed (or 'deprecated') features.\n\nWhich makes me suspect the code didn't do anything. But code that doesn't execute can't be exploited.\n\nMy only guess: Something that was added during testing/debugging, then left in because of laziness/inertia.",
    "permalink": "/r/MacOS/comments/1k1awe3/are_there_unused_chunks_of_code_in_macos_heres/",
    "timestamp": "2025-04-17T11:54:40",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "They most likely mean **removed vulnerable code and replaced it with secure code**. It's just the standard way to write these change notes.",
        "level": 0
      },
      {
        "score": 1,
        "text": "This would be my assumption.  Well, “replaced it with *hopefully* secure code” anyway.",
        "level": 1
      }
    ]
  },
  {
    "cves": [
      "CVE-2020-13443"
    ],
    "cve_counts": {
      "CVE-2020-13443": 1
    },
    "title": "Trying to understand Cloudflare Managed Ruleset",
    "text": "So while working with an error, that I tried resolving through Cloudflare Managed Ruleset, I noticed something.\n\nIssue: Blocked Content Notification displays when we upload two files with the same type through the webapp. When the user uploads two different filetypes, then the request goea through without any issues.\n\nOn inspecting the RayID in Splunk, the Security Rule Description indicated CVE-2020-13443\n\nI read through the CVE, but I couldn't understand how the issue and the rule causing the block action are related.\n\nCan someone help with this? Or tell me any appropriate community to post this in.",
    "permalink": "/r/CloudFlare/comments/1k1ckw6/trying_to_understand_cloudflare_managed_ruleset/",
    "timestamp": "2025-04-17T13:18:42",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-50264"
    ],
    "cve_counts": {
      "CVE-2024-50264": 1
    },
    "title": "Kernel-Hack-Drill: Environment For Developing Linux Kernel Exploits",
    "text": "[Alexander Popov](https://x.com/a13xp0p0v) published the [slides](https://a13xp0p0v.github.io/img/Alexander_Popov-Kernel_Hack_Drill-Zer0Con.pdf) from his talk at Zer0Con 2025. In this talk, he presented the [kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill) open-source project and showed how it helped him to exploit CVE-2024-50264 in the Linux kernel.",
    "permalink": "/r/linkersec/comments/1k1eq4r/kernelhackdrill_environment_for_developing_linux/",
    "timestamp": "2025-04-17T14:51:48",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32433",
      "CVE-2024-50264",
      "CVE-2025-24994",
      "CVE-2025-21299",
      "CVE-2025-24076",
      "CVE-2025-27840",
      "CVE-2025-24054",
      "CVE-2025-31201"
    ],
    "cve_counts": {
      "CVE-2025-27840": 1,
      "CVE-2024-50264": 1,
      "CVE-2025-31201": 2,
      "CVE-2025-21299": 2,
      "CVE-2025-24076": 1,
      "CVE-2025-24054": 1,
      "CVE-2025-32433": 1,
      "CVE-2025-24994": 1
    },
    "title": "🔥 Top 10 Trending CVEs (17/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. CVE-2025-27840**\n\n- 📝 A potential security vulnerability affects Espressif ESP32 chips, enabling undocumented HCI commands, including 0xFC02 (Write memory). The severity is moderate (CVSS 6.8), and exploitation requires high attack complexity with no user interaction needed (AV:P/AC:H). No known instances of exploitation in the wild have been reported as of yet (CISA KEV: false).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**2. CVE-2024-50264**\n\n- 📝 In the Linux Kernel, a Use-After-Free vulnerability (CVE xxx) exists within vsock/virtio. During loopback communication, a dangling pointer can be created in vsk->trans, potentially leading to memory corruption when using versions specified in the description. The severity is high due to potential code execution and data disclosure (CVSS: 7.8, AV:L). No known exploitation has been observed in the wild (CISA KEV: false).\n\n- 📅 **Published:** 19/11/2024\n- 📈 **CVSS:** 7.8\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**3. CVE-2025-31201**\n\n- 📝 A remotely exploitable code bypass vulnerability for Pointer Authentication (CVSS 6.8, AV:N/AC:H) was identified, potentially exploited in targeted attacks against iOS. The affected systems include tvOS 18.4.1, visionOS 2.4.1, iOS 18.4.1, iPadOS 18.4.1, and macOS Sequoia 15.4.1. Apply updates to mitigate risk.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**4. CVE-2025-21299**\n\n- 📝 A Windows Kerberos Security Feature Bypass vulnerability (CVSS 7.1, remotely exploitable) has been identified, potentially allowing elevation of privileges on affected systems running specific versions. No known active exploitation has been reported yet. It is recommended to apply relevant patches promptly for mitigation.\n\n- 📅 **Published:** 14/01/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**5. CVE-2025-24076**\n\n- 📝 A locally-exploitable privilege escalation vulnerability (CVSS 7.3, L/L/L/R/U/U/H) exists within Windows Cross Device Service. This flaw could allow an attacker with authorized access to elevate their privileges locally. No known exploitation in the wild has been reported at this time. Ensure affected systems are up-to-date.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 7.3\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H\n\n---\n\n**6. CVE-2025-21299**\n\n- 📝 A potential Windows Kerberos Security Feature Bypass vulnerability (CVSS 7.1) has been identified, allowing for local attack vectors (AV:L/AC:L). This flaw could lead to high impact on confidentiality (C:H) and integrity (I:H), but no known exploitation in the wild has been reported (KEV:false) as of yet. It's recommended to ensure affected systems are up-to-date with relevant patches to mitigate risk.\n\n- 📅 **Published:** 14/01/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**7. CVE-2025-24054**\n\n- 📝 A network spoofing vulnerability (CVSS v3.1: AV:N/AC:L) exists in certain Windows NTLM implementations, with a severity score of 6.5. This issue allows an unauthorized attacker to manipulate file names or paths over a network, potentially leading to sensitive information disclosure (C:H). Currently, there is no confirmed evidence that it has been exploited in the wild. It is recommended to update affected versions as soon as possible.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N\n\n---\n\n**8. CVE-2025-32433**\n\n- 📝 Remote Code Execution vulnerability in Erlang/OTP (versions prior to OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20) allows unauthenticated RCE via SSH protocol message handling. Affected systems may be compromised without valid credentials. Patch to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20 is available; temporary workarounds include disabling SSH or firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**9. CVE-2025-31201**\n\n- 📝 A remotely exploitable bypass of Pointer Authentication was discovered in tvOS, visionOS, iOS, iPadOS, and macOS. This issue may allow an attacker with arbitrary read-write capability to potentially breach security, with Apple reporting its use in a targeted sophisticated attack against specific individuals on iOS (fixed in v18.4.1 for all mentioned platforms). CISA KEV: false, suggesting it has not been exploited in the wild beyond these targeted instances.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**10. CVE-2025-24994**\n\n- 📝 A locally-exploitable privilege escalation vulnerability (CVSS 7.3) exists in Windows Cross Device Service, enabling an authorized attacker to elevate privileges. Verify affected versions match those listed in the description for potential security impact.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 7.3\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H\n\n---\n\nLet us know if you're tracking any of these or if something flew under the radar or find any issues with the provided details.",
    "permalink": "/r/CVEWatch/comments/1k1dswv/top_10_trending_cves_17042025/",
    "timestamp": "2025-04-17T14:12:19",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32433",
      "CVE-2024-50264",
      "CVE-2025-24994",
      "CVE-2025-21299",
      "CVE-2025-24076",
      "CVE-2025-27840",
      "CVE-2025-24054",
      "CVE-2025-29809",
      "CVE-2025-31201"
    ],
    "cve_counts": {
      "CVE-2025-27840": 1,
      "CVE-2024-50264": 1,
      "CVE-2025-31201": 1,
      "CVE-2025-21299": 2,
      "CVE-2025-24076": 1,
      "CVE-2025-24054": 1,
      "CVE-2025-32433": 1,
      "CVE-2025-24994": 1,
      "CVE-2025-29809": 1
    },
    "title": "🔥 Top 10 Trending CVEs (17/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. CVE-2025-27840**\n\n- 📝 A potential security vulnerability affects Espressif ESP32 chips, enabling undocumented HCI commands, including 0xFC02 (Write memory). The severity is moderate, and exploitation requires high attack complexity with no user interaction needed. No known instances of exploitation in the wild have been reported as of yet.\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**2. CVE-2024-50264**\n\n- 📝 In the Linux Kernel, a Use-After-Free vulnerability exists within vsock/virtio. During loopback communication, a dangling pointer can be created in vsk->trans, potentially leading to memory corruption when using versions specified in the description. The severity is high due to potential code execution and data disclosure. No known exploitation has been observed in the wild.\n\n- 📅 **Published:** 19/11/2024\n- 📈 **CVSS:** 7.8\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**3. CVE-2025-31201**\n\n- 📝 A remotely exploitable code bypass vulnerability for Pointer Authentication was identified, potentially exploited in targeted attacks against iOS. The affected systems include tvOS 18.4.1, visionOS 2.4.1, iOS 18.4.1, iPadOS 18.4.1, and macOS Sequoia 15.4.1. Apply updates to mitigate risk.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**4. CVE-2025-21299**\n\n- 📝 A Windows Kerberos Security Feature Bypass vulnerability has been identified, potentially allowing elevation of privileges on affected systems running specific versions. No known active exploitation has been reported yet. It is recommended to apply relevant patches promptly for mitigation.\n\n- 📅 **Published:** 14/01/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**5. CVE-2025-24076**\n\n- 📝 A locally-exploitable privilege escalation vulnerability exists within Windows Cross Device Service. This flaw could allow an attacker with authorized access to elevate their privileges locally. No known exploitation in the wild has been reported at this time. Ensure affected systems are up-to-date.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 7.3\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H\n\n---\n\n**6. CVE-2025-21299**\n\n- 📝 A potential Windows Kerberos Security Feature Bypass vulnerability has been identified, allowing for local attack vectors. This flaw could lead to high impact on confidentiality and integrity, but no known exploitation in the wild has been reported as of yet. It's recommended to ensure affected systems are up-to-date with relevant patches to mitigate risk.\n\n- 📅 **Published:** 14/01/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**7. CVE-2025-24054**\n\n- 📝 A network spoofing vulnerability exists in certain Windows NTLM implementations, with a severity score of 6.5. This issue allows an unauthorized attacker to manipulate file names or paths over a network, potentially leading to sensitive information disclosure. Currently, there is no confirmed evidence that it has been exploited in the wild. It is recommended to update affected versions as soon as possible.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N\n\n---\n\n**8. CVE-2025-32433**\n\n- 📝 Remote Code Execution vulnerability in Erlang/OTP (versions prior to OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20) allows unauthenticated RCE via SSH protocol message handling. Affected systems may be compromised without valid credentials. Patch to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20 is available; temporary workarounds include disabling SSH or firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**9. CVE-2025-24994**\n\n- 📝 A locally-exploitable privilege escalation vulnerability exists in Windows Cross Device Service, enabling an authorized attacker to elevate privileges. Verify affected versions match those listed in the description for potential security impact.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 7.3\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H\n\n---\n\n**10. CVE-2025-29809**\n\n- 📝 A locally-exploitable vulnerability exists in Windows Kerberos due to insecure storage of sensitive information. This issue allows an authorized attacker to bypass a security feature, potentially leading to high confidentiality and integrity impacts. Currently, there is no evidence of it being exploited in the wild.\n\n- 📅 **Published:** 08/04/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\nLet us know if you're tracking any of these or if something flew under the radar or find any issues with the provided details.",
    "permalink": "/r/CVEWatch/comments/1k1ds1z/top_10_trending_cves_17042025/",
    "timestamp": "2025-04-17T14:11:17",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-31201",
      "CVE-2025-31200"
    ],
    "cve_counts": {
      "CVE-2025-31200": 1,
      "CVE-2025-31201": 1
    },
    "title": "Urgent Security Alert: Update iOS 18.4.1 Now to Combat Major Flaws",
    "text": "\n**Apple has released an urgent update to fix two serious zero-day vulnerabilities that may have been exploited in sophisticated attacks.**\n\n**Key Points:**\n\n- Update your iPhone and other Apple devices immediately to patch critical vulnerabilities.\n- The flaws, discovered by security researchers, can allow hackers to execute remote code and bypass security protections.\n- These vulnerabilities potentially affect many Apple devices, including the latest iPhones and Macs.\n\nApple recently rolled out an emergency security update for iOS 18.4.1 in response to the discovery of two significant zero-day vulnerabilities. The first flaw, identified as CVE-2025-31200, resides within CoreAudio and allows malicious actors to execute remote code on targeted devices by sending specially crafted audio files. The second vulnerability, CVE-2025-31201, allows hackers to bypass the iOS security feature known as Pointer Authentication, exposing the device to further exploitation.\n\nThese vulnerabilities are not only concerning due to their technical nature but also because they have been linked to sophisticated attacks against well-known individuals, showing that targeted cyber threats are becoming more commonplace. While Apple has managed to patch these vulnerabilities swiftly, the existence of such flaws underlines the importance of timely software updates for all users, as attacks based on similar vulnerabilities often trickle down to the general public shortly after being discovered. Thus, ensuring that your devices are up to date is critical in maintaining security against potential exploits.\n\nHave you updated your Apple devices yet, and what steps do you take to ensure your cybersecurity?\n\n**Learn More:** [Tom's Guide](https://www.tomsguide.com/computing/online-security/apple-releases-emergency-security-update-after-extremely-sophisticated-attack-update-your-iphone-ipad-and-mac-right-now)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k1fqzy/urgent_security_alert_update_ios_1841_now_to/",
    "timestamp": "2025-04-17T15:34:35",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2021-20035"
    ],
    "cve_counts": {
      "CVE-2021-20035": 2
    },
    "title": "SonicWall Command Injection Flaw Under Attack",
    "text": "\n**CISA alerts that a critical command injection vulnerability in SonicWall devices is being actively exploited by threat actors.**\n\n**Key Points:**\n\n- CVE-2021-20035 affects SonicWall SMA100 Series appliances with a CVSS score of 7.2.\n- The vulnerability allows remote authenticated attackers to execute arbitrary operating system commands.\n- Compromised devices could lead to sensitive data theft, ransomware deployment, or broader network access.\n\nThe Cybersecurity and Infrastructure Security Agency (CISA) has raised alarms about a severe command injection vulnerability in SonicWall SMA100 appliances, classified as CVE-2021-20035. This flaw, which affects widely used models including the SMA 200 and 400, has been confirmed to be exploited in real-world scenarios, underscoring the urgent need for organizations to address it. The vulnerability allows attackers with remote authenticated access to leverage system commands via the management interface, which could enable total control over the affected devices. The agency’s advisory serves as a reminder of the ongoing threats surrounding network security infrastructure.\n\nGiven that the SonicWall appliances often act as critical network gateways, a successful breach poses significant security risks. An attacker could potentially manipulate the device to steal sensitive data, deploy ransomware, or create a foothold for further network infiltration. Organizations are urged to apply security patches and implement rigorous monitoring practices to detect any signs of compromise. Since the deadline for federal agencies to address this vulnerability is approaching, it is a crucial reminder for all companies relying on similar technology systems to prioritize their cybersecurity measures.\n\nWhat steps has your organization taken to address recent vulnerabilities like the SonicWall issue?\n\n**Learn More:** [Cyber Security News](https://cybersecuritynews.com/sonicwall-command-injection-vulnerability/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k1fqr2/sonicwall_command_injection_flaw_under_attack/",
    "timestamp": "2025-04-17T15:34:20",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2021-35587"
    ],
    "cve_counts": {
      "CVE-2021-35587": 1
    },
    "title": "CISA Warns of Credential Risks Linked to Oracle Cloud Compromise",
    "text": "\n**Unauthorized access to Oracle Cloud's legacy environment poses substantial risks to organizations and individuals, according to CISA's high-priority advisory.**\n\n**Key Points:**\n\n- Approximately 6 million records may have been exfiltrated, including sensitive credentials.\n- Exploitation of a critical vulnerability in Oracle Access Manager allowed unauthorized access.\n- Password resets and enhanced security measures are crucial for affected users.\n\nThe Cybersecurity and Infrastructure Security Agency (CISA) has issued an urgent alert following alarming reports of a possible compromise within Oracle Cloud's infrastructure. An individual known as 'rose87168' claimed to have extracted around 6 million sensitive records from Oracle’s Single Sign-On and Lightweight Directory Access Protocol systems. These records could potentially include critical information such as usernames, passwords, and authentication tokens, which are essential for maintaining secure access to various services. CISA emphasizes the serious ramifications of credential leaks, as they may allow threat actors to escalate privileges, maneuver through corporate networks, and launch targeted phishing attacks.\n\nCISA’s advisory also pinpoints that the attacker exploited CVE-2021-35587, a severe vulnerability that has remained unpatched in Oracle Fusion Middleware since 2014. While Oracle refutes claims of a significant breach, the investigation by CrowdStrike and the FBI reveals the potential for long-term unauthorized access if sensitive credential material has indeed been exposed. CISA urges organizations and individual users to take immediate action, such as resetting passwords and implementing multi-factor authentication, to mitigate the fallout from this incident. The agency's guidance highlights that lax management of credentials, especially hardcoded in scripts and applications, can lead to dire security breaches if compromised.\n\nWhat steps do you think organizations should prioritize in response to this alert?\n\n**Learn More:** [Cyber Security News](https://cybersecuritynews.com/cisa-warns-of-credential-risks-linked/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k1fq5q/cisa_warns_of_credential_risks_linked_to_oracle/",
    "timestamp": "2025-04-17T15:33:37",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2021-20035"
    ],
    "cve_counts": {
      "CVE-2021-20035": 2
    },
    "title": "SonicWall SMA Devices Under Cyber Threat Due to Exploited Vulnerability",
    "text": "\n**CISA has flagged a high-severity vulnerability in SonicWall SMA devices that poses serious security risks due to active exploitation.**\n\n**Key Points:**\n\n- CVE-2021-20035 vulnerability allows remote command injection.\n- Affected devices include SMA 200, 210, 400, 410, and 500v series.\n- Federal agencies must mitigate this issue by May 7, 2025.\n\nThe Cybersecurity and Infrastructure Security Agency (CISA) has identified a severe vulnerability affecting SonicWall Secure Mobile Access (SMA) devices, specifically those within the 100 Series range. Tracked as CVE-2021-20035 with a CVSS score of 7.2, this security flaw enables a remote authenticated attacker to perform operating system command injection. Such exploitation can lead to unauthorized code execution, posing a significant risk to network integrity and data security. SonicWall's advisory highlighted the vulnerability's scope, indicating that it allows harmful commands to be executed under a 'nobody' user, thereby bypassing some access controls designed to protect the system. With the confirmation of active exploitation, it becomes a pressing issue for organizations relying on these devices to transport sensitive data safely.\n\nThe specific models affected include the SMA 200, 210, 400, 410, and 500v across multiple environments such as ESX, KVM, AWS, and Azure. Users of these devices running vulnerable software versions are urged to update immediately to safeguard against potential breaches. SonicWall has acknowledged that this vulnerability could indeed be exploited in the wild, highlighting the importance of timely action and patch management. Notably, all Federal Civilian Executive Branch agencies are required to implement necessary security measures by the specified deadline, underlining how critical this issue is for national cybersecurity efforts.\n\nWhat steps is your organization taking to address actively exploited vulnerabilities in your cybersecurity infrastructure?\n\n**Learn More:** [The Hacker News](https://thehackernews.com/2025/04/cisa-flags-actively-exploited.html)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k1flzj/sonicwall_sma_devices_under_cyber_threat_due_to/",
    "timestamp": "2025-04-17T15:28:46",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2021-20035"
    ],
    "cve_counts": {
      "CVE-2021-20035": 2
    },
    "title": "SonicWall Reveals Old Vulnerability Now Actively Exploited",
    "text": "\n**A vulnerability in SonicWall's SMA 100 series, previously considered low risk, is now being actively exploited, impacting customer security.**\n\n**Key Points:**\n\n- SonicWall updated its advisory to indicate active exploitation of CVE-2021-20035.\n- The vulnerability allows remote authenticated attacks to execute arbitrary commands.\n- Originally rated as medium severity, it has been reclassified to high severity with a CVSS score of 7.2.\n- Exploitation may involve additional vulnerabilities, as authentication is required for attacks.\n- CISA has added the vulnerability to its Known Exploited Vulnerabilities catalog.\n\nThis week, SonicWall raised alarms regarding a vulnerability in its SMA 100 series, identified as CVE-2021-20035, initially patched in 2021. The flaw permits a remote authenticated attacker to inject arbitrary commands, which could lead to unauthorized code execution. The company is now warning customers about the risk of this vulnerability being exploited in the wild, following a revision of its security advisory. The exploit's re-election to high severity underscores the risk posed, especially for organizations using affected models. The SMA models include 200, 210, 400, 410, and 500v, all of which are vulnerable if running outdated software versions.\n\n\n\n**Learn More:** [Security Week](https://www.securityweek.com/sonicwall-flags-old-vulnerability-as-actively-exploited/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k1fky7/sonicwall_reveals_old_vulnerability_now_actively/",
    "timestamp": "2025-04-17T15:27:36",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-32433"
    ],
    "cve_counts": {
      "CVE-2025-32433": 2
    },
    "title": "Erlang/OTP SSH Vulnerability May Risk Thousands of Devices",
    "text": "\n**A critical flaw in Erlang/OTP's SSH library exposes numerous devices to potential remote hacking attacks.**\n\n**Key Points:**\n\n- CVE-2025-32433 allows attackers to execute arbitrary code via unauthenticated SSH connections.\n- The vulnerability affects any SSH server using Erlang/OTP's SSH library, including many Cisco and Ericsson devices.\n- The flaw may lead to unauthorized data access, complete device takeover, or even ransomware installation.\n\nA security vulnerability has been discovered in the Erlang/OTP SSH library, assigned the CVE identifier CVE-2025-32433, with a maximum CVSS score of 10, indicating its critical severity. This flaw allows an attacker to send connection protocol messages prior to the completion of SSH authentication, effectively enabling them to execute arbitrary code within the SSH daemon. If the SSH daemon runs with root access, which is common, this poses a severe risk as it gives attackers complete control over affected devices. The direct implications could be detrimental, affecting high-availability systems used across sectors including finance and telecommunications.\n\nResearchers warn that systems relying on Erlang/OTP, particularly those connected to remote access services, are highly susceptible. The wide adoption of Erlang in the infrastructure of major companies like Cisco and Ericsson increases the potential impact. Compromised devices could result in unauthorized access to highly sensitive information or serve as a platform for launching further attacks, such as ransomware. Users have been advised to implement firewall rules as a stopgap measure until a comprehensive patch is applied, specifically in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20 that were recently released to mitigate the risk.\n\nWhat measures can organizations take to better protect themselves from such vulnerabilities?\n\n**Learn More:** [Security Week](https://www.securityweek.com/critical-erlang-otp-ssh-flaw-exposes-many-servers-to-remote-hacking/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k1fkod/erlangotp_ssh_vulnerability_may_risk_thousands_of/",
    "timestamp": "2025-04-17T15:27:18",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-57699",
      "CVE-2021-33813",
      "CVE-2025-20236"
    ],
    "cve_counts": {
      "CVE-2024-57699": 1,
      "CVE-2021-33813": 1,
      "CVE-2025-20236": 1
    },
    "title": "Atlassian and Cisco Issue Critical Patches for High-Severity Vulnerabilities",
    "text": "\n**Atlassian and Cisco have addressed multiple severe vulnerabilities that could lead to remote code execution and other significant security risks.**\n\n**Key Points:**\n\n- Atlassian released seven updates patching four vulnerabilities across its popular products.\n- Cisco patched multiple security flaws in Webex App, Secure Network Analytics, and Nexus Dashboard.\n- Both companies reported no known exploits of these vulnerabilities in the wild.\n\nAtlassian has released critical patches for four high-severity vulnerabilities affecting its products, including Bamboo, Confluence, and Jira. These flaws, some publicly disclosed nearly six years ago, included remote code execution risks and denial-of-service vulnerabilities. The updates specifically address defects tracked as CVE-2024-57699 and CVE-2021-33813, which could be exploited to compromise systems without any authentication required. This highlights a pressing need for organizations using these software solutions to apply updates promptly to protect their environments from potential attacks.\n\nSimilarly, Cisco has rolled out patches for several security vulnerabilities in their software offerings. Among these is a high-severity flaw in the Webex App (CVE-2025-20236), which can allow attackers to execute arbitrary code through deceptive meeting invites. Additionally, Cisco's patches fixed medium-severity issues that could grant authenticated attackers unintended shell access or reveal valid LDAP usernames to unauthenticated users. Both companies have indicated they are not aware of these vulnerabilities being actively exploited, yet the patches should be applied to mitigate future risks.\n\nWhat steps can organizations take to ensure they are promptly addressing vulnerabilities in their software?\n\n**Learn More:** [Security Week](https://www.securityweek.com/vulnerabilities-patched-in-atlassian-cisco-products/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k1fkj4/atlassian_and_cisco_issue_critical_patches_for/",
    "timestamp": "2025-04-17T15:27:08",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-32860"
    ],
    "cve_counts": {
      "CVE-2025-32860": 1
    },
    "title": "CVE Alert: CVE-2025-32860",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k1mkkd/cve_alert_cve202532860/",
    "timestamp": "2025-04-17T20:16:24",
    "article_text": "A vulnerability has been identified in TeleControl Server Basic (All versions < V3.1.2.2). The affected application is vulnerable to SQL injection through the internally used 'UnlockWebServerGatewaySettings' method. This could allow an authenticated remote attacker to bypass authorization controls, to read from and write to the application's database and execute code with \"NT AUTHORITY\\NetworkService\" permissions. A successful attack requires the attacker to be able to access port 8000 on a system where a vulnerable version of the affected application is executed on.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32858"
    ],
    "cve_counts": {
      "CVE-2025-32858": 1
    },
    "title": "CVE Alert: CVE-2025-32858",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k1rt3b/cve_alert_cve202532858/",
    "timestamp": "2025-04-18T00:16:22",
    "article_text": "A vulnerability has been identified in TeleControl Server Basic (All versions < V3.1.2.2). The affected application is vulnerable to SQL injection through the internally used 'UpdateWebServerGatewaySettings' method. This could allow an authenticated remote attacker to bypass authorization controls, to read from and write to the application's database and execute code with \"NT AUTHORITY\\NetworkService\" permissions. A successful attack requires the attacker to be able to access port 8000 on a system where a vulnerable version of the affected application is executed on.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-24054": 1
    },
    "title": "CVE-2025-24054 Under Active Attack—Steals NTLM Credentials on File Download",
    "text": "",
    "permalink": "/r/u_TheCyberSecurityHub/comments/1k1wtgh/cve202524054_under_active_attacksteals_ntlm/",
    "timestamp": "2025-04-18T04:52:04",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-28101"
    ],
    "cve_counts": {
      "CVE-2025-28101": 1
    },
    "title": "CVE Alert: CVE-2025-28101",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k1x794/cve_alert_cve202528101/",
    "timestamp": "2025-04-18T05:16:22",
    "article_text": "An arbitrary file deletion vulnerability in the /post/{postTitle} component of flaskBlog v2.6.1 allows attackers to delete article titles created by other users via supplying a crafted POST request.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-24054": 1,
      "cve-2025-24054": 2
    },
    "title": "CVE-2025-24054: Windows Vulnerability Exploited to Steal Credentials",
    "text": "A recently patched Windows vulnerability is under active attack, with phishing campaigns distributing files that leak NTLM credentials upon minimal interaction. Ensure your systems are updated to protect against this threat.​\n\nFull story: [https://thehackernews.com/2025/04/cve-2025-24054-under-active.html](https://thehackernews.com/2025/04/cve-2025-24054-under-active.html)\n\n",
    "permalink": "/r/cybersecurityexams/comments/1k1ypzn/cve202524054_windows_vulnerability_exploited_to/",
    "timestamp": "2025-04-18T06:58:13",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-24054": 1
    },
    "title": "CVE-2025-24054, NTLM Exploit in the Wild",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1k1ypl1/cve202524054_ntlm_exploit_in_the_wild/",
    "timestamp": "2025-04-18T06:57:23",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-24054": 1
    },
    "title": "CVE-2025-24054 - Exploited in the wild",
    "text": "This is quite an interesting vulnerability with CVSS 6.5 and EPSS 0.6% it would fly under the radar for most companies.\n\nBut it has already been used to target government agencies, requires almost no interaction from users (drag and drop, right click or simply navigating to a directory) and can leak user credentials. I know its Friday but you should patch now! ",
    "permalink": "/r/CVEWatch/comments/1k1yytu/cve202524054_exploited_in_the_wild/",
    "timestamp": "2025-04-18T07:15:34",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-31201",
      "CVE-2025-27840",
      "CVE-2025-21299",
      "CVE-2025-24054",
      "CVE-2025-24859",
      "CVE-2025-32433",
      "CVE-2025-31200",
      "CVE-2025-29471",
      "CVE-2025-29809"
    ],
    "cve_counts": {
      "CVE-2025-24054": 1,
      "CVE-2025-27840": 1,
      "CVE-2025-31201": 1,
      "CVE-2025-21299": 1,
      "CVE-2025-24859": 1,
      "CVE-2025-29809": 1,
      "CVE-2025-31200": 1,
      "CVE-2025-32433": 1,
      "CVE-2025-29471": 1
    },
    "title": "🔥 Top 10 Trending CVEs (18/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. CVE-2025-24054**\n\n- 📝 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🛡️ **CISA KEV:** Yes\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N\n\n---\n\n**2. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**3. CVE-2025-31201**\n\n- 📝 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**4. CVE-2025-21299**\n\n- 📝 Windows Kerberos Security Feature Bypass Vulnerability\n\n- 📅 **Published:** 14/01/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**5. CVE-2025-24859**\n\n- 📝 A session management vulnerability exists in Apache Roller before version 6.1.5 where active user sessions are not properly invalidated after password changes. When a users password is changed, either by the user themselves or by an administrator, existing sessions remain active and usable. This allows continued access to the application through old sessions even after password changes, potentially enabling unauthorized access if credentials were compromised. This issue affects Apache Roller versions up to and including 6.1.4. The vulnerability is fixed in Apache Roller 6.1.5 by implementing centralized session management that properly invalidates all active sessions when passwords are changed or users are disabled.\n\n- 📅 **Published:** 14/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X\n\n---\n\n**6. CVE-2025-29809**\n\n- 📝 Insecure storage of sensitive information in Windows Kerberos allows an authorized attacker to bypass a security feature locally.\n\n- 📅 **Published:** 08/04/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**7. Unknown CVE**\n\n- 📝 \n\n- 📅 **Published:** N/A\n\n---\n\n**8. CVE-2025-31200**\n\n- 📝 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 7.5\n- 🛡️ **CISA KEV:** Yes\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H\n\n---\n\n**9. CVE-2025-32433**\n\n- 📝 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**10. CVE-2025-29471**\n\n- 📝 Cross Site Scripting vulnerability in Nagios Log Server v.2024R1.3.1 allows a remote attacker to execute arbitrary code via a payload into the Email field.\n\n- 📅 **Published:** 15/04/2025\n- 📈 **CVSS:** 8.3\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H\n\n---\n\nLet us know if you're tracking any of these or if something flew under the radar or find any issues with the provided details.",
    "permalink": "/r/CVEWatch/comments/1k21cij/top_10_trending_cves_18042025/",
    "timestamp": "2025-04-18T10:06:45",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2021-47671"
    ],
    "cve_counts": {
      "CVE-2021-47671": 1
    },
    "title": "CVE Alert: CVE-2021-47671",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k21hqh/cve_alert_cve202147671/",
    "timestamp": "2025-04-18T10:16:23",
    "article_text": "In the Linux kernel, the following vulnerability has been resolved: can: etas_es58x: es58x_rx_err_msg(): fix memory leak in error path In es58x_rx_err_msg(), if can->do_set_mode() fails, the function directly returns without calling netif_rx(skb). This means that the skb previously allocated by alloc_can_err_skb() is not freed. In other terms, this is a memory leak. This patch simply removes the return statement in the error branch and let the function continue. Issue was found with GCC -fanalyzer, please follow the link below for details.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-42599",
      "CVE-2025-32422",
      "CVE-2025-31200",
      "CVE-2025-31201",
      "CVE-2025-29471",
      "CVE-2025-21299",
      "CVE-2025-24859",
      "CVE-2025-27840",
      "CVE-2025-29809"
    ],
    "cve_counts": {
      "CVE-2025-31200": 1,
      "CVE-2025-21299": 1,
      "CVE-2025-27840": 2,
      "CVE-2025-42599": 1,
      "CVE-2025-24859": 1,
      "CVE-2025-32422": 1,
      "CVE-2025-29809": 1,
      "CVE-2025-31201": 1,
      "CVE-2025-29471": 1
    },
    "title": "🔥 Top 10 Trending CVEs (18/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. CVE-2025-31200**\n\n- 📝 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 7.5\n- 🛡️ **CISA KEV:** Yes\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H\n\n---\n\n**2. CVE-2025-21299**\n\n- 📝 Windows Kerberos Security Feature Bypass Vulnerability\n\n- 📅 **Published:** 14/01/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**3. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**4. CVE-2025-42599**\n\n- 📝 n/a\n\n- 📈 **CVSS:** 0\n- 🧭 **Vector:** n/a\n\n---\n\n**5. CVE-2025-24859**\n\n- 📝 A session management vulnerability exists in Apache Roller before version 6.1.5 where active user sessions are not properly invalidated after password changes. When a users password is changed, either by the user themselves or by an administrator, existing sessions remain active and usable. This allows continued access to the application through old sessions even after password changes, potentially enabling unauthorized access if credentials were compromised. This issue affects Apache Roller versions up to and including 6.1.4. The vulnerability is fixed in Apache Roller 6.1.5 by implementing centralized session management that properly invalidates all active sessions when passwords are changed or users are disabled.\n\n- 📅 **Published:** 14/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X\n\n---\n\n**6. CVE-2025-32422**\n\n- 📝 n/a\n\n- 📈 **CVSS:** 0\n- 🧭 **Vector:** n/a\n\n---\n\n**7. CVE-2025-29809**\n\n- 📝 Insecure storage of sensitive information in Windows Kerberos allows an authorized attacker to bypass a security feature locally.\n\n- 📅 **Published:** 08/04/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**8. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**9. CVE-2025-31201**\n\n- 📝 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🛡️ **CISA KEV:** Yes\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**10. CVE-2025-29471**\n\n- 📝 Cross Site Scripting vulnerability in Nagios Log Server v.2024R1.3.1 allows a remote attacker to execute arbitrary code via a payload into the Email field.\n\n- 📅 **Published:** 15/04/2025\n- 📈 **CVSS:** 8.3\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H\n\n---\n\nLet us know if you're tracking any of these or if something flew under the radar or find any issues with the provided details.",
    "permalink": "/r/CVEWatch/comments/1k262t8/top_10_trending_cves_18042025/",
    "timestamp": "2025-04-18T14:19:39",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32433",
      "CVE-2025-32422",
      "CVE-2025-31201",
      "CVE-2025-27840",
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-32422": 1,
      "CVE-2025-32433": 2,
      "CVE-2025-24054": 2,
      "CVE-2025-27840": 4,
      "CVE-2025-31201": 1
    },
    "title": "🔥 Top 10 Trending CVEs (18/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. CVE-2025-32422**\n\n- 📝 n/a\n\n- 📈 **CVSS:** 0\n- 🧭 **Vector:** n/a\n\n---\n\n**2. CVE-2025-32433**\n\n- 📝 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**3. CVE-2025-24054**\n\n- 📝 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🛡️ **CISA KEV:** Yes\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N\n\n---\n\n**4. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**5. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**6. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**7. CVE-2025-24054**\n\n- 📝 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🛡️ **CISA KEV:** Yes\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N\n\n---\n\n**8. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**9. CVE-2025-32433**\n\n- 📝 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**10. CVE-2025-31201**\n\n- 📝 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\nLet us know if you're tracking any of these or if something flew under the radar or find any issues with the provided details.",
    "permalink": "/r/CVEWatch/comments/1k25x45/top_10_trending_cves_18042025/",
    "timestamp": "2025-04-18T14:12:48",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-29824"
    ],
    "cve_counts": {
      "CVE-2025-29824": 1
    },
    "title": "Security Watch 4/18/25",
    "text": "On K12TechPro, we've launched a weekly cyber threat intelligence and vulnerability newsletter with NTP and K12TechPro. We'll post the \"public\" news to k12sysadmin from each newsletter. For the full \"k12 techs only\" portion (no middle schoolers, bad guys, vendors, etc. allowed), log into [k12techpro.com](http://k12techpro.com) and visit the Cybersecurity Hub.\n\n**SSL/TLS Lifespan Cut Proposed**\n\nStarting in 2029, SSL/TLS certificates may be limited to just 47 days—down from 398. This push for better security means automation tools like ACME will become essential for certificate management. \n\n**Smarter Phishing on the Rise**\n\n“Precision-Validated Phishing” is making traditional defenses less effective. These attacks confirm the validity of email addresses before launching, bypassing automated detection tools and targeting users more effectively.\n\n**An Odd Ransomware Case**\n\nNTP recently handled a unique incident involving amateur attackers using AI and 7-Zip instead of traditional ransomware. The attack was neutralized, but it highlights a growing trend of less-skilled actors targeting smaller organizations. *See full newsletter for details.*\n\n**CVE-2025-29824: SYSTEM-Level Exploit**\n\nA new Windows vulnerability allows attackers to gain SYSTEM privileges. Patched as of April 2025 (OS Build 26100.3775), this flaw emphasizes the need for regular updates, strong monitoring, and endpoint protection.",
    "permalink": "/r/k12sysadmin/comments/1k25ww6/security_watch_41825/",
    "timestamp": "2025-04-18T14:12:34",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-20236"
    ],
    "cve_counts": {
      "CVE-2025-20236": 2
    },
    "title": "Cisco Webex Bug Exposes Users to Remote Code Execution Risks",
    "text": "\n**A recently discovered vulnerability in Cisco Webex allows attackers to execute arbitrary code on users' devices through crafted meeting invite links.**\n\n**Key Points:**\n\n- CVE-2025-20236 allows unauthenticated attackers to exploit a flaw in Webex's URL parser.\n- Users may unknowingly download malicious files by clicking on deceptive meeting links.\n- The vulnerability affects all installations of Cisco Webex App regardless of OS.\n- Immediate software updates are required as there are no workarounds.\n- Cisco has also patched other critical vulnerabilities this week.\n\nCisco recently released a security advisory regarding a significant vulnerability identified as CVE-2025-20236 in its Webex application. This issue enables unauthenticated attackers to achieve remote code execution on user devices after tricking individuals into clicking on specially crafted meeting invite links. The situation is particularly alarming as the flaw exists due to insufficient input validation in how Cisco Webex processes these links, potentially exposing users to serious security breaches without their awareness.\n\nOnce a user clicks on a malicious meeting invite, they may be led to download harmful files, enabling the attacker to execute arbitrary commands on the victim's system. The implications are vast, as this vulnerability could affect companies of all sizes relying on Webex for communication. Users must apply the latest security patches provided by Cisco to safeguard their systems, as failing to do so could potentially lead to unauthorized access and exploitation of sensitive information. Furthermore, Cisco has addressed additional vulnerabilities simultaneously, underscoring the importance of maintaining updated software across all platforms.\n\nHow can organizations enhance their cybersecurity awareness to prevent falling victim to such vulnerabilities?\n\n**Learn More:** [Bleeping Computer](https://www.bleepingcomputer.com/news/security/cisco-webex-bug-lets-hackers-gain-code-execution-via-meeting-links/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k27zk9/cisco_webex_bug_exposes_users_to_remote_code/",
    "timestamp": "2025-04-18T15:41:09",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2021-20035"
    ],
    "cve_counts": {
      "CVE-2021-20035": 1
    },
    "title": "SonicWall SMA VPN Devices Under Active Attack Since January",
    "text": "\n**A critical remote code execution vulnerability in SonicWall SMA VPN devices has been actively exploited since January 2025, raising concerns for organizations using these appliances.**\n\n**Key Points:**\n\n- Vulnerability CVE-2021-20035 allows remote execution of commands on SonicWall SMA VPN devices.\n- The issue impacts multiple SMA 100 series models and was first patched in September 2021.\n- Cybersecurity firm Arctic Wolf reports that attacks leveraging this flaw began as early as January 2025.\n\nThe vulnerability identified in SonicWall's Secure Mobile Access (SMA) appliances, particularly in models SMA 200, 210, 400, 410, and 500v, poses a significant threat to organizations that utilize these devices for secure remote access. Originally classified as a medium severity denial-of-service vulnerability, the flaw has been reclassified to high severity due to its potential for remote code execution, which could allow malicious actors to execute arbitrary commands with limited privileges. This change underscores the urgency for affected organizations to act swiftly to mitigate risk.\n\nCybersecurity analysts, including Arctic Wolf, have tracked the exploitation of this vulnerability since January 2025. The exploitation involves leveraging a default admin account that is widely considered insecure, which casts further doubt on the security practices of organizations using these devices. SonicWall has advised immediate action, including limiting VPN access, deactivating unnecessary accounts, enabling multi-factor authentication, and resetting all local account passwords to prevent potential breaches. Furthermore, the inclusion of this vulnerability in the CISA's Known Exploited Vulnerabilities catalog signals its severe implications for national security and the broad necessity for organizations to update their security measures.\n\nWhat steps have you taken to secure your VPN devices against known vulnerabilities?\n\n**Learn More:** [Bleeping Computer](https://www.bleepingcomputer.com/news/security/sonicwall-sma-vpn-devices-targeted-in-attacks-since-january/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k27ycq/sonicwall_sma_vpn_devices_under_active_attack/",
    "timestamp": "2025-04-18T15:39:46",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-24054": 4,
      "cve-2025-24054": 1
    },
    "title": "Critical Flaw CVE-2025-24054 Active—NTLM Credentials at Risk",
    "text": "\n**A medium-severity flaw in Windows is under active attack, allowing attackers to steal NTLM credentials through minimal user interaction.**\n\n**Key Points:**\n\n- CVE-2025-24054 exploits NTLM authentication protocol, allowing credential theft.\n- Active exploitation reported since March 19, targeting institutions in Poland and Romania.\n- Attackers use phishing campaigns to deliver malicious .library-ms files for NTLM hash extraction.\n\nThe recently identified CVE-2025-24054 vulnerability in Microsoft Windows poses a significant risk by allowing unauthorized attackers to spoof NTLM credentials across networks. NTLM is an outdated authentication protocol that has been largely deprecated in favor of newer technologies like Kerberos. However, its continued presence in Windows environments presents an enduring target for cybercriminals. This flaw can be triggered with minimal user interaction, such as a simple click or file inspection, illustrating how effortless it is for attackers to exploit it. Once activated, it can lead to the extraction of NTLM hashes, which can be further leveraged in malicious campaigns to compromise systems.\n\nFollowing the initial reports of exploitation, cybersecurity firms identified numerous campaigns, particularly targeting government and private institutions in regions like Poland and Romania. Attackers have been observed distributing malicious links via emails, using trusted cloud storage platforms to evade detection. As these malicious .library-ms files take advantage of a ZIP archive format, they facilitate an SMB authentication request, enabling hash leaks with no direct execution of the files required. This seamless method of infiltration showcases the urgency for organizations to patch these vulnerabilities promptly and address the risks associated with NTLM to safeguard their networks against credential theft and further attacks.\n\nHow can organizations better protect themselves against vulnerabilities like CVE-2025-24054 in their networks?\n\n**Learn More:** [The Hacker News](https://thehackernews.com/2025/04/cve-2025-24054-under-active.html)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k27y3f/critical_flaw_cve202524054_activentlm_credentials/",
    "timestamp": "2025-04-18T15:39:27",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-21299",
      "CVE-2025-31200",
      "CVE-2025-29471",
      "CVE-2025-27840",
      "CVE-2025-32433",
      "CVE-2025-31201",
      "CVE-2025-24054",
      "CVE-2025-24859",
      "CVE-2025-42599"
    ],
    "cve_counts": {
      "CVE-2025-27840": 2,
      "CVE-2025-31201": 1,
      "CVE-2025-42599": 1,
      "CVE-2025-32433": 1,
      "CVE-2025-29471": 1,
      "CVE-2025-31200": 1,
      "CVE-2025-21299": 1,
      "CVE-2025-24054": 1,
      "CVE-2025-24859": 1
    },
    "title": "🔥 Top 10 Trending CVEs (18/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**2. CVE-2025-31201**\n\n- 📝 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 0\n- 🧭 **Vector:** n/a\n\n---\n\n**3. CVE-2025-42599**\n\n- 📝 Active! mail 6 BuildInfo: 6.60.05008561 and earlier contains a stack-based buffer overflow vulnerability. Receiving a specially crafted request created and sent by a remote unauthenticated attacker may lead to arbitrary code execution and/or a denial-of-service (DoS) condition.\n\n- 📅 **Published:** 18/04/2025\n- 📈 **CVSS:** 9.8\n- 🧭 **Vector:** CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**4. CVE-2025-32433**\n\n- 📝 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**5. CVE-2025-29471**\n\n- 📝 Cross Site Scripting vulnerability in Nagios Log Server v.2024R1.3.1 allows a remote attacker to execute arbitrary code via a payload into the Email field.\n\n- 📅 **Published:** 15/04/2025\n- 📈 **CVSS:** 0\n- 🧭 **Vector:** n/a\n\n---\n\n**6. CVE-2025-31200**\n\n- 📝 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 0\n- 🧭 **Vector:** n/a\n\n---\n\n**7. CVE-2025-21299**\n\n- 📝 \n\n- 📅 **Published:** 14/01/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N/E:U/RL:O/RC:C\n\n---\n\n**8. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**9. CVE-2025-24054**\n\n- 📝 \n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C\n\n---\n\n**10. CVE-2025-24859**\n\n- 📝 A session management vulnerability exists in Apache Roller before version 6.1.5 where active user sessions are not properly invalidated after password changes. When a users password is changed, either by the user themselves or by an administrator, existing sessions remain active and usable. This allows continued access to the application through old sessions even after password changes, potentially enabling unauthorized access if credentials were compromised. This issue affects Apache Roller versions up to and including 6.1.4. The vulnerability is fixed in Apache Roller 6.1.5 by implementing centralized session management that properly invalidates all active sessions when passwords are changed or users are disabled.\n\n- 📅 **Published:** 14/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X\n\n---\n\nLet us know if you're tracking any of these or if something flew under the radar or find any issues with the provided details.",
    "permalink": "/r/CVEWatch/comments/1k29ss2/top_10_trending_cves_18042025/",
    "timestamp": "2025-04-18T16:57:15",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3248"
    ],
    "cve_counts": {
      "CVE-2025-3248": 1
    },
    "title": "POC - Remote and unauthenticated attacker can send crafted HTTP requests to execute arbitrary code - CVE-2025-3248",
    "text": "",
    "permalink": "/r/ExploitDev/comments/1k2ac0m/poc_remote_and_unauthenticated_attacker_can_send/",
    "timestamp": "2025-04-18T17:19:07",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-27840",
      "CVE-2025-21299",
      "CVE-2025-31200",
      "CVE-2025-32422",
      "CVE-2025-29809",
      "CVE-2025-31201",
      "CVE-2025-24054",
      "CVE-2025-32433",
      "CVE-2025-29471",
      "CVE-2025-42599"
    ],
    "cve_counts": {
      "CVE-2025-31201": 1,
      "CVE-2025-31200": 1,
      "CVE-2025-29471": 1,
      "CVE-2025-32422": 1,
      "CVE-2025-27840": 1,
      "CVE-2025-42599": 1,
      "CVE-2025-32433": 1,
      "CVE-2025-24054": 1,
      "CVE-2025-21299": 1,
      "CVE-2025-29809": 1
    },
    "title": "🔥 Top 10 Trending CVEs (18/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. CVE-2025-31201**\n\n- 📝 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n\n---\n\n**2. CVE-2025-31200**\n\n- 📝 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 7.5\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H\n\n---\n\n**3. CVE-2025-29471**\n\n- 📝 Cross Site Scripting vulnerability in Nagios Log Server v.2024R1.3.1 allows a remote attacker to execute arbitrary code via a payload into the Email field.\n\n- 📅 **Published:** 15/04/2025\n- 📈 **CVSS:** 8.3\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H\n\n---\n\n**4. CVE-2025-32422**\n\n- 📝 n/a\n\n- 📈 **CVSS:** 0\n- 🧭 **Vector:** n/a\n\n---\n\n**5. CVE-2025-27840**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n\n---\n\n**6. CVE-2025-42599**\n\n- 📝 Active! mail 6 BuildInfo: 6.60.05008561 and earlier contains a stack-based buffer overflow vulnerability. Receiving a specially crafted request created and sent by a remote unauthenticated attacker may lead to arbitrary code execution and/or a denial-of-service (DoS) condition.\n\n- 📅 **Published:** 18/04/2025\n- 📈 **CVSS:** 9.8\n- 🧭 **Vector:** CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n---\n\n**7. CVE-2025-32433**\n\n- 📝 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n\n---\n\n**8. CVE-2025-24054**\n\n- 📝 NTLM Hash Disclosure Spoofing Vulnerability\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C\n\n---\n\n**9. CVE-2025-21299**\n\n- 📝 Windows Kerberos Security Feature Bypass Vulnerability\n\n- 📅 **Published:** 14/01/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N/E:U/RL:O/RC:C\n\n---\n\n**10. CVE-2025-29809**\n\n- 📝 Windows Kerberos Security Feature Bypass Vulnerability\n\n- 📅 **Published:** 08/04/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N/E:U/RC:C\n\n---\n\nLet us know if you're tracking any of these or if something flew under the radar or find any issues with the provided details.",
    "permalink": "/r/CVEWatch/comments/1k2abt9/top_10_trending_cves_18042025/",
    "timestamp": "2025-04-18T17:18:54",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-29824",
      "CVE-2025-27840",
      "CVE-2025-31200",
      "CVE-2025-29809",
      "CVE-2025-29471",
      "CVE-2025-31201",
      "CVE-2025-24054",
      "CVE-2025-32433",
      "CVE-2025-21299",
      "CVE-2025-42599"
    ],
    "cve_counts": {
      "CVE-2025-31201": 2,
      "CVE-2025-31200": 2,
      "CVE-2025-29471": 2,
      "CVE-2025-29824": 2,
      "CVE-2025-27840": 2,
      "CVE-2025-42599": 2,
      "CVE-2025-32433": 2,
      "CVE-2025-24054": 2,
      "CVE-2025-21299": 2,
      "CVE-2025-29809": 2
    },
    "title": "🔥 Top 10 Trending CVEs (18/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. [CVE-2025-31201](https://nvd.nist.gov/vuln/detail/CVE-2025-31201)**\n\n- 📝 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n- 📣 **Mentions:** 24\n- ⚠️ **Priority:** 1+\n\n---\n\n**2. [CVE-2025-31200](https://nvd.nist.gov/vuln/detail/CVE-2025-31200)**\n\n- 📝 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 7.5\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 31\n- ⚠️ **Priority:** 1+\n\n---\n\n**3. [CVE-2025-29471](https://nvd.nist.gov/vuln/detail/CVE-2025-29471)**\n\n- 📝 Cross Site Scripting vulnerability in Nagios Log Server v.2024R1.3.1 allows a remote attacker to execute arbitrary code via a payload into the Email field.\n\n- 📅 **Published:** 15/04/2025\n- 📈 **CVSS:** 8.3\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H\n- 📣 **Mentions:** 1\n- ⚠️ **Priority:** 2\n\n---\n\n**4. [CVE-2025-29824](https://nvd.nist.gov/vuln/detail/CVE-2025-29824)**\n\n- 📝 A use-after-free vulnerability in the Windows Common Log File System Driver that allows an authenticated local attacker to elevate privileges to SYSTEM level.\n- 📈 **CVSS:** 7.8\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n- ⚠️ **Priority:** 1+\n\n---\n\n**5. [CVE-2025-27840](https://nvd.nist.gov/vuln/detail/CVE-2025-27840)**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n- 📣 **Mentions:** 16\n- ⚠️ **Priority:** 2\n\n---\n\n**6. [CVE-2025-42599](https://nvd.nist.gov/vuln/detail/CVE-2025-42599)**\n\n- 📝 Active! mail 6 BuildInfo: 6.60.05008561 and earlier contains a stack-based buffer overflow vulnerability. Receiving a specially crafted request created and sent by a remote unauthenticated attacker may lead to arbitrary code execution and/or a denial-of-service (DoS) condition.\n\n- 📅 **Published:** 18/04/2025\n- 📈 **CVSS:** 9.8\n- 🧭 **Vector:** CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 6\n- ⚠️ **Priority:** 4\n\n---\n\n**7. [CVE-2025-32433](https://nvd.nist.gov/vuln/detail/CVE-2025-32433)**\n\n- 📝 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n- 📣 **Mentions:** 44\n- ⚠️ **Priority:** 2\n\n---\n\n**8. [CVE-2025-24054](https://nvd.nist.gov/vuln/detail/CVE-2025-24054)**\n\n- 📝 NTLM Hash Disclosure Spoofing Vulnerability\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C\n- 📣 **Mentions:** 36\n- ⚠️ **Priority:** 1+\n\n---\n\n**9. [CVE-2025-21299](https://nvd.nist.gov/vuln/detail/CVE-2025-21299)**\n\n- 📝 Windows Kerberos Security Feature Bypass Vulnerability\n\n- 📅 **Published:** 14/01/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N/E:U/RL:O/RC:C\n- 📣 **Mentions:** 7\n- ⚠️ **Priority:** 2\n\n---\n\n**10. [CVE-2025-29809](https://nvd.nist.gov/vuln/detail/CVE-2025-29809)**\n\n- 📝 Windows Kerberos Security Feature Bypass Vulnerability\n\n- 📅 **Published:** 08/04/2025\n- 📈 **CVSS:** 7.1\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N/E:U/RC:C\n- 📣 **Mentions:** 2\n- ⚠️ **Priority:** 2\n\n---\n\nLet us know if you're tracking any of these or if you find any issues with the provided details, priority scores come from [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer).",
    "permalink": "/r/CVEWatch/comments/1k2cptw/top_10_trending_cves_18042025/",
    "timestamp": "2025-04-18T18:59:22",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-24054": 1
    },
    "title": "Microsoft Windows NTLM Hash Disclosure Spoofing Vulnerability (CVE-2025-24054)",
    "text": "",
    "permalink": "/r/systemtek/comments/1k2byk1/microsoft_windows_ntlm_hash_disclosure_spoofing/",
    "timestamp": "2025-04-18T18:27:26",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-25364"
    ],
    "cve_counts": {
      "CVE-2025-25364": 1
    },
    "title": "CVE-2025-25364: Speedify VPN MacOS privilege Escalation",
    "text": "",
    "permalink": "/r/netsec/comments/1k2bpp5/cve202525364_speedify_vpn_macos_privilege/",
    "timestamp": "2025-04-18T18:17:10",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-2492"
    ],
    "cve_counts": {
      "CVE-2025-2492": 1
    },
    "title": "ASUS routers with AiCloud vulnerable to auth bypass exploit",
    "text": "ASUS warnt vor einer Sicherheitslücke zur Umgehung der Authentifizierung in Routern mit aktivierter AiCloud, die die unbefugte Ausführung von Funktionen auf dem Gerät ermöglichen könnte. ASUS warnt vor einer Sicherheitslücke zur Umgehung der Authentifizierung (CVE-2025-2492, CVSS v4-Score: 9,2), die Router mit aktivierter AiCloud betrifft. Ein Remote-Angreifer kann die Schwachstelle ausnutzen, um unbefugte Funktionen auf dem Gerät auszuführen",
    "permalink": "/r/Computersicherheit/comments/1k2e7ps/asus_routers_with_aicloud_vulnerable_to_auth/",
    "timestamp": "2025-04-18T20:03:34",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-39535"
    ],
    "cve_counts": {
      "CVE-2025-39535": 1
    },
    "title": "CVE Alert: CVE-2025-39535",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k2ei8k/cve_alert_cve202539535/",
    "timestamp": "2025-04-18T20:16:25",
    "article_text": "Authentication Bypass Using an Alternate Path or Channel vulnerability in appsbd Vitepos allows Authentication Abuse. This issue affects Vitepos: from n/a through 3.1.7.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-39464"
    ],
    "cve_counts": {
      "CVE-2025-39464": 1
    },
    "title": "CVE Alert: CVE-2025-39464",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k2jng9/cve_alert_cve202539464/",
    "timestamp": "2025-04-19T00:16:24",
    "article_text": "Improper Neutralization of Input During Web Page Generation (‘Cross-site Scripting’) vulnerability in rtowebsites AdminQuickbar allows Reflected XSS. This issue affects AdminQuickbar: from n/a through 1.9.1.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2021-30858"
    ],
    "cve_counts": {
      "CVE-2021-30858": 1
    },
    "title": "Exploiting a Web-Based UAF",
    "text": "Hello! I've recently been getting into exploit dev. I am still very much a beginner to this type of stuff, however. The vulnerability I've been trying to exploit is tracked as CVE-2021-30858. (although this appears to be a completely different bug?) The successful PoC I've found is as follows:\n\n    var fontFace1 = new FontFace(\"font1\", \"\", {});\n    var fontFaceSet = new FontFaceSet([fontFace1]);\n    fontFace1.family = \"font2\";\n\nMy question is: How would I go about turning this into something more? What would be a good first step to turn this into an exploit?  \nThanks in advance! :3",
    "permalink": "/r/ExploitDev/comments/1k2op5m/exploiting_a_webbased_uaf/",
    "timestamp": "2025-04-19T05:04:48",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-24914"
    ],
    "cve_counts": {
      "CVE-2025-24914": 1
    },
    "title": "CVE Alert: CVE-2025-24914",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k2nxv1/cve_alert_cve202524914/",
    "timestamp": "2025-04-19T04:16:23",
    "article_text": "When installing Nessus to a non-default location on a Windows host, Nessus versions prior to 10.8.4 did not enforce secure permissions for sub-directories. This could allow for local privilege escalation if users had not secured the directories in the non-default installation location. – CVE-2025-24914",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32433"
    ],
    "cve_counts": {
      "CVE-2025-32433": 1
    },
    "title": "How I Used AI to Create a Working Exploit for CVE-2025-32433 Before Public PoCs Existed",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1k2rdgy/how_i_used_ai_to_create_a_working_exploit_for/",
    "timestamp": "2025-04-19T08:09:05",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "PoC: https://github.com/ProDefense/CVE-2025-32433",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-2492"
    ],
    "cve_counts": {
      "CVE-2025-2492": 1
    },
    "title": "CVE-2025-2492: ASUS Router AiCloud vulnerability - \"An improper authentication control vulnerability exists in certain ASUS router firmware series. This vulnerability can be triggered by a crafted request, potentially leading to unauthorized execution of functions\"",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1k2rcjh/cve20252492_asus_router_aicloud_vulnerability_an/",
    "timestamp": "2025-04-19T08:07:15",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-2492"
    ],
    "cve_counts": {
      "CVE-2025-2492": 1
    },
    "title": "ASUS Router AiCloud vulnerability - CVE-2025-2492. An improper authentication control vulnerability exists in certain ASUS router firmware series. This vulnerability can be triggered by a crafted request, potentially leading to unauthorized execution of functions.",
    "text": "",
    "permalink": "/r/worldTechnology/comments/1k2s43i/asus_router_aicloud_vulnerability_cve20252492_an/",
    "timestamp": "2025-04-19T09:04:08",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2021-20035"
    ],
    "cve_counts": {
      "CVE-2021-20035": 1
    },
    "title": "Credential Access Campaign Targeting SonicWall SMA Devices Linked to CVE-2021-20035 since January 2025",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1k2rf4w/credential_access_campaign_targeting_sonicwall/",
    "timestamp": "2025-04-19T08:12:29",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "Advisory update from SonicWall: \n\"This vulnerability is believed to be actively exploited in the wild. As a precautionary measure, SonicWall PSIRT has updated the summary and revised the CVSS score to 7.2,\" SonicWall said.\n\nWas originally CVSS 6.5 \n\nArticle: https://www.bleepingcomputer.com/news/security/sonicwall-sma-vpn-devices-targeted-in-attacks-since-january/",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-32433"
    ],
    "cve_counts": {
      "CVE-2025-32433": 1
    },
    "title": "CVE-2025-32433: Critical Erlang/OTP SSH Vulnerability (CVSS 10) - \"RCE via unauthenticated SSH messages in Erlang/OTP\" - PoC out see other post",
    "text": "",
    "permalink": "/r/blueteamsec/comments/1k2re6a/cve202532433_critical_erlangotp_ssh_vulnerability/",
    "timestamp": "2025-04-19T08:10:29",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-30158"
    ],
    "cve_counts": {
      "CVE-2025-30158": 1
    },
    "title": "CVE Alert: CVE-2025-30158",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k2s9zc/cve_alert_cve202530158/",
    "timestamp": "2025-04-19T09:16:20",
    "article_text": "NamelessMC is a free, easy to use & powerful website software for Minecraft servers. In version 2.1.4 and prior, the forum allows users to post iframe elements inside forum topics/comments/feed with no restriction on the iframe’s width and height attributes. This allows an authenticated attacker to perform a UI-based denial of service (DoS) by injecting oversized iframes that block the forum UI and disrupt normal user interactions. This issue has been patched in version 2.2.0.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2018-15473",
      "CVE-2023-48795"
    ],
    "cve_counts": {
      "CVE-2018-15473": 1,
      "CVE-2023-48795": 1
    },
    "title": "SSH Hardening & Offensive Mastery – Practical SSH Cibersecurity Book",
    "text": "We recently released a technical book at DSDSec called **SSH Hardening & Offensive Mastery**, focused entirely on securing and attacking SSH environments. It's built around real-world labs and is intended for sysadmins, red/blue teams, and cybersecurity professionals.\n\nTopics covered include:\n\n* SSH hardening (2FA, Fail2Ban, Suricata)\n* Secure tunneling (local, remote, dynamic, UDP)\n* Evasion techniques and SSH agent hijacking\n* Malware propagation via dynamic tunnels (Metasploit + BlueKeep example)\n* CVE analysis: CVE-2018-15473, Terrapin (CVE-2023-48795)\n* LD\\_PRELOAD and other environment-based techniques\n* Tooling examples using Tcl/Expect and Perl\n* All supported by hands-on labs\n\n📘 Free PDF:  \n[https://dsdsec.com/wp-content/uploads/2025/04/SSH-Hardening-and-Offensive-Mastery.pdf](https://dsdsec.com/wp-content/uploads/2025/04/SSH-Hardening-and-Offensive-Mastery.pdf)\n\nMore info:  \n[https://dsdsec.com/publications/](https://dsdsec.com/publications/)\n\nWould love to hear thoughts or feedback from anyone working with SSH security.",
    "permalink": "/r/Hacking_Tutorials/comments/1k2un8a/ssh_hardening_offensive_mastery_practical_ssh/",
    "timestamp": "2025-04-19T12:00:08",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32433",
      "CVE-2025-31201",
      "CVE-2025-27840",
      "CVE-2024-13059",
      "CVE-2025-31200",
      "CVE-2025-29927",
      "CVE-2025-42599",
      "CVE-2025-29824",
      "CVE-2024-53141",
      "CVE-2025-24054"
    ],
    "cve_counts": {
      "CVE-2025-31201": 2,
      "CVE-2024-53141": 2,
      "CVE-2025-29927": 2,
      "CVE-2025-31200": 2,
      "CVE-2025-29824": 2,
      "CVE-2025-27840": 2,
      "CVE-2024-13059": 2,
      "CVE-2025-42599": 2,
      "CVE-2025-32433": 2,
      "CVE-2025-24054": 2
    },
    "title": "🔥 Top 10 Trending CVEs (19/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. [CVE-2025-31201](https://nvd.nist.gov/vuln/detail/CVE-2025-31201)**\n\n- 📝 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n- 📣 **Mentions:** 24\n- ⚠️ **Priority:** 1+\n\n---\n\n**2. [CVE-2024-53141](https://nvd.nist.gov/vuln/detail/CVE-2024-53141)**\n\n- 📝 In the Linux kernel, the following vulnerability has been resolved: netfilter: ipset: add missing range check in bitmap_ip_uadt When tb[IPSET_ATTR_IP_TO] is not present but tb[IPSET_ATTR_CIDR] exists, the values of ip and ip_to are slightly swapped. Therefore, the range check for ip should be done later, but this part is missing and it seems that the vulnerability occurs. So we should add missing range checks and remove unnecessary range checks.\n\n- 📅 **Published:** 06/12/2024\n- 📈 **CVSS:** 7.8\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 4\n- ⚠️ **Priority:** 2\n\n---\n\n**3. [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)**\n\n- 📝 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.\n\n- 📅 **Published:** 21/03/2025\n- 📈 **CVSS:** 9.1\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N\n- 📣 **Mentions:** 186\n- ⚠️ **Priority:** 2\n\n---\n\n**4. [CVE-2025-31200](https://nvd.nist.gov/vuln/detail/CVE-2025-31200)**\n\n- 📝 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 7.5\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 31\n- ⚠️ **Priority:** 1+\n\n---\n\n**5. [CVE-2025-29824](https://nvd.nist.gov/vuln/detail/CVE-2025-29824)**\n\n- 📝 A use-after-free vulnerability in the Windows Common Log File System Driver that allows an authenticated local attacker to elevate privileges to SYSTEM level.\n- 📈 **CVSS:** 7.8\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n- ⚠️ **Priority:** 1+\n\n---\n\n**6. [CVE-2025-27840](https://nvd.nist.gov/vuln/detail/CVE-2025-27840)**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n- 📣 **Mentions:** 16\n- ⚠️ **Priority:** 2\n\n---\n\n**7. [CVE-2024-13059](https://nvd.nist.gov/vuln/detail/CVE-2024-13059)**\n\n- 📝 A vulnerability in mintplex-labs/anything-llm prior to version 1.3.1 allows for path traversal due to improper handling of non-ASCII filenames in the multer library. This vulnerability can lead to arbitrary file write, which can subsequently result in remote code execution. The issue arises when the filename transformation introduces ../ sequences, which are not sanitized by multer, allowing attackers with manager or admin roles to write files to arbitrary locations on the server.\n\n- 📅 **Published:** 10/02/2025\n- 📈 **CVSS:** 7.2\n- 🧭 **Vector:** CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 5\n- ⚠️ **Priority:** 2\n\n---\n\n**8. [CVE-2025-42599](https://nvd.nist.gov/vuln/detail/CVE-2025-42599)**\n\n- 📝 Active! mail 6 BuildInfo: 6.60.05008561 and earlier contains a stack-based buffer overflow vulnerability. Receiving a specially crafted request created and sent by a remote unauthenticated attacker may lead to arbitrary code execution and/or a denial-of-service (DoS) condition.\n\n- 📅 **Published:** 18/04/2025\n- 📈 **CVSS:** 9.8\n- 🧭 **Vector:** CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 6\n- ⚠️ **Priority:** 4\n\n---\n\n**9. [CVE-2025-32433](https://nvd.nist.gov/vuln/detail/CVE-2025-32433)**\n\n- 📝 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n- 📣 **Mentions:** 44\n- ⚠️ **Priority:** 2\n\n---\n\n**10. [CVE-2025-24054](https://nvd.nist.gov/vuln/detail/CVE-2025-24054)**\n\n- 📝 NTLM Hash Disclosure Spoofing Vulnerability\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C\n- 📣 **Mentions:** 36\n- ⚠️ **Priority:** 1+\n\n---\n\nLet us know if you're tracking any of these or if you find any issues with the provided details, priority scores come from [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer).",
    "permalink": "/r/CVEWatch/comments/1k2vbuk/top_10_trending_cves_19042025/",
    "timestamp": "2025-04-19T12:38:28",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-2950"
    ],
    "cve_counts": {
      "CVE-2025-2950": 1
    },
    "title": "CVE Alert: CVE-2025-2950",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k2x8xr/cve_alert_cve20252950/",
    "timestamp": "2025-04-19T14:16:22",
    "article_text": "IBM i 7.3, 7.4, 7.5, and 7.5 is vulnerable to a host header injection attack caused by improper neutralization of HTTP header content by IBM Navigator for i. An authenticated user can manipulate the host header in HTTP requests to change domain/IP address which may lead to unexpected behavior.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2021-20035"
    ],
    "cve_counts": {
      "CVE-2021-20035": 1
    },
    "title": "SonicWall Authenticated SMA100 Arbitrary Command Injection Vulnerability Is Been Exploited (CVE-2021-20035)",
    "text": "",
    "permalink": "/r/systemtek/comments/1k2z9s7/sonicwall_authenticated_sma100_arbitrary_command/",
    "timestamp": "2025-04-19T15:47:22",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32433"
    ],
    "cve_counts": {
      "CVE-2025-32433": 2
    },
    "title": "Critical Erlang/OTP SSH Flaw Exposed: Urgent Action Required",
    "text": "\n**A severe vulnerability in the Erlang/OTP SSH protocol allows attackers to execute remote code without authentication, making patching essential.**\n\n**Key Points:**\n\n- Public exploits for CVE-2025-32433 are now available, posing serious risk.\n- Devices running Erlang/OTP, especially in telecom and databases, are vulnerable.\n- Previous version fixes require immediate updates, but many systems may be hard to patch quickly.\n- The SSH protocol is widely used, increasing the risk of widespread exploitation.\n\nResearchers have disclosed a critical SSH vulnerability in Erlang/OTP, tracked as CVE-2025-32433, which allows unauthenticated attackers to execute code remotely. This vulnerability stems from a flaw in the SSH protocol's message handling, enabling attackers to send messages prior to authentication. The flaw impacts numerous devices across telecom infrastructures, databases, and high-availability systems, drastically elevating the stakes for organizations relying on these technologies.\n\nPatch updates are available in versions 25.3.2.10 and 26.2.4, but many affected systems may face significant challenges in updating due to their entrenched positions in critical infrastructure. Researchers noted that the flaw is surprisingly easy to exploit, with multiple cybersecurity experts now having created and shared public proof-of-concept (PoC) exploits. This growing availability of exploits heightens the urgency for organizations to patch their systems swiftly, as threat actors are likely to scan for vulnerable devices imminently. Given that over 600,000 IP addresses are running Erlang/OTP, the potential for widespread compromise is considerable, particularly with targeted exploitation by state-sponsored actors becoming an ever-looming threat.\n\nWhat measures are you taking to ensure your systems are protected against this vulnerability?\n\n**Learn More:** [Bleeping Computer](https://www.bleepingcomputer.com/news/security/public-exploits-released-for-critical-erlang-otp-ssh-flaw-patch-now/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k2zwv6/critical_erlangotp_ssh_flaw_exposed_urgent_action/",
    "timestamp": "2025-04-19T16:15:45",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-2492"
    ],
    "cve_counts": {
      "CVE-2025-2492": 2
    },
    "title": "Critical Security Flaw in ASUS AiCloud Routers Exposes Users to Remote Attacks",
    "text": "\n**ASUS has revealed a serious vulnerability in its AiCloud-enabled routers that could allow remote attackers to access and execute unauthorized functions.**\n\n**Key Points:**\n\n- Vulnerability CVE-2025-2492 has a critical score of 9.2, indicating severe risk.\n- Affected routers require immediate firmware updates to safeguard against exploitation.\n- Users are advised to create strong, unique passwords for their networks and devices.\n\nASUS recently confirmed a critical security vulnerability affecting its AiCloud-enabled routers, identified as CVE-2025-2492. This flaw has a CVSS score of 9.2 out of 10, marking it as extremely high-risk. The vulnerability stems from improper authentication controls in specific ASUS router firmware, which can be exploited by crafted requests, potentially allowing remote attackers to execute unauthorized actions on affected devices.\n\nIn response to this threat, ASUS has issued firmware updates to rectify the issue. Users with affected firmware versions, including 3.0.0.4_3823, 0.0.4_3863, 0.0.4_388, and 3.0.0.6_102, must promptly update to the latest version. Until then, users should ensure their login and Wi-Fi passwords are robust. ASUS emphasizes stronger passwords, recommending combinations of capital letters, numbers, and symbols, avoid using the same passwords across devices, and refrain from predictable patterns such as consecutive numbers or letters. Alternatively, if users are unable to apply patches immediately, disabling AiCloud and any external access services is highly recommended to reduce potential exposure.\n\nWhat steps are you taking to secure your devices against vulnerabilities like this?\n\n**Learn More:** [The Hacker News](https://thehackernews.com/2025/04/asus-confirms-critical-flaw-in-aicloud.html)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k2zwqm/critical_security_flaw_in_asus_aicloud_routers/",
    "timestamp": "2025-04-19T16:15:35",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-3786"
    ],
    "cve_counts": {
      "CVE-2025-3786": 1
    },
    "title": "CVE Alert: CVE-2025-3786",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k33z4t/cve_alert_cve20253786/",
    "timestamp": "2025-04-19T19:16:22",
    "article_text": "A vulnerability was found in Tenda AC15 up to 15.03.05.19 and classified as critical. This issue affects the function fromSetWirelessRepeat of the file /goform/WifiExtraSet. The manipulation of the argument mac leads to buffer overflow. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3799"
    ],
    "cve_counts": {
      "CVE-2025-3799": 1
    },
    "title": "CVE Alert: CVE-2025-3799",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k3ec82/cve_alert_cve20253799/",
    "timestamp": "2025-04-20T04:16:25",
    "article_text": "A vulnerability, which was classified as critical, was found in WCMS 11. Affected is an unknown function of the file app/controllers/AnonymousController.php. The manipulation of the argument email/username leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-2111"
    ],
    "cve_counts": {
      "CVE-2025-2111": 1
    },
    "title": "CVE Alert: CVE-2025-2111",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k3io26/cve_alert_cve20252111/",
    "timestamp": "2025-04-20T09:16:27",
    "article_text": "The Insert Headers And Footers plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 3.1.1. This is due to missing or incorrect nonce validation on the ‘custom_plugin_set_option’ function. This makes it possible for unauthenticated attackers to update arbitrary options on the WordPress site via a forged request granted they can trick a site administrator into performing an action such as clicking on a link. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site. The ‘WPBRIGADE_SDK__DEV_MODE’ constant must be set to ‘true’ to exploit the vulnerability.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32433"
    ],
    "cve_counts": {
      "CVE-2025-32433": 1
    },
    "title": "NVD - CVE-2025-32433 - Fixed in OTP 27.3.3, OTP 26.2.5.11, and OTP 25.3.2.20",
    "text": "",
    "permalink": "/r/erlang/comments/1k3n5l8/nvd_cve202532433_fixed_in_otp_2733_otp_262511_and/",
    "timestamp": "2025-04-20T13:59:18",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3284"
    ],
    "cve_counts": {
      "CVE-2025-3284": 1
    },
    "title": "CVE Alert: CVE-2025-3284",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k3niam/cve_alert_cve20253284/",
    "timestamp": "2025-04-20T14:16:30",
    "article_text": "The User Registration & Membership – Custom Registration Form, Login Form, and User Profile plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 5.1.3. This is due to missing or incorrect nonce validation on the user_registration_pro_delete_account() function. This makes it possible for unauthenticated attackers to force delete users, including administrators, via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32433",
      "CVE-2024-53141",
      "CVE-2025-2492",
      "CVE-2025-24054",
      "CVE-2025-27840",
      "CVE-2025-31201",
      "CVE-2024-13059",
      "CVE-2025-27520",
      "CVE-2025-31200",
      "CVE-2025-42599"
    ],
    "cve_counts": {
      "CVE-2025-31201": 2,
      "CVE-2024-53141": 2,
      "CVE-2025-2492": 2,
      "CVE-2025-31200": 2,
      "CVE-2025-27520": 2,
      "CVE-2025-27840": 2,
      "CVE-2024-13059": 2,
      "CVE-2025-42599": 2,
      "CVE-2025-32433": 2,
      "CVE-2025-24054": 2
    },
    "title": "🔥 Top 10 Trending CVEs (20/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. [CVE-2025-31201](https://nvd.nist.gov/vuln/detail/CVE-2025-31201)**\n\n- 📝 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n- 📣 **Mentions:** 24\n- ⚠️ **Priority:** 1+\n\n---\n\n**2. [CVE-2024-53141](https://nvd.nist.gov/vuln/detail/CVE-2024-53141)**\n\n- 📝 In the Linux kernel, the following vulnerability has been resolved: netfilter: ipset: add missing range check in bitmap_ip_uadt When tb[IPSET_ATTR_IP_TO] is not present but tb[IPSET_ATTR_CIDR] exists, the values of ip and ip_to are slightly swapped. Therefore, the range check for ip should be done later, but this part is missing and it seems that the vulnerability occurs. So we should add missing range checks and remove unnecessary range checks.\n\n- 📅 **Published:** 06/12/2024\n- 📈 **CVSS:** 0\n- 🧭 **Vector:** n/a\n- 📣 **Mentions:** 4\n- ⚠️ **Priority:** 2\n\n---\n\n**3. [CVE-2025-2492](https://nvd.nist.gov/vuln/detail/CVE-2025-2492)**\n\n- 📝 An improper authentication control vulnerability exists in AiCloud. This vulnerability can be triggered by a crafted request, potentially leading to unauthorized execution of functions. Refer to the ASUS Router AiCloud vulnerability section on the ASUS Security Advisory for more information.\n\n- 📅 **Published:** 18/04/2025\n- 📈 **CVSS:** 9.2\n- 🧭 **Vector:** CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N\n- 📣 **Mentions:** 15\n- ⚠️ **Priority:** 0\n\n---\n\n**4. [CVE-2025-31200](https://nvd.nist.gov/vuln/detail/CVE-2025-31200)**\n\n- 📝 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 7.5\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 31\n- ⚠️ **Priority:** 1+\n\n---\n\n**5. [CVE-2025-27520](https://nvd.nist.gov/vuln/detail/CVE-2025-27520)**\n\n- 📝 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. A Remote Code Execution (RCE) vulnerability caused by insecure deserialization has been identified in the latest version (v1.4.2) of BentoML. It allows any unauthenticated user to execute arbitrary code on the server. It exists an unsafe code segment in serde.py. This vulnerability is fixed in 1.4.3.\n\n- 📅 **Published:** 04/04/2025\n- 📈 **CVSS:** 9.8\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 15\n- ⚠️ **Priority:** 0\n\n---\n\n**6. [CVE-2025-27840](https://nvd.nist.gov/vuln/detail/CVE-2025-27840)**\n\n- 📝 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).\n\n- 📅 **Published:** 08/03/2025\n- 📈 **CVSS:** 6.8\n- 🧭 **Vector:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L\n- 📣 **Mentions:** 16\n- ⚠️ **Priority:** 2\n\n---\n\n**7. [CVE-2024-13059](https://nvd.nist.gov/vuln/detail/CVE-2024-13059)**\n\n- 📝 A vulnerability in mintplex-labs/anything-llm prior to version 1.3.1 allows for path traversal due to improper handling of non-ASCII filenames in the multer library. This vulnerability can lead to arbitrary file write, which can subsequently result in remote code execution. The issue arises when the filename transformation introduces ../ sequences, which are not sanitized by multer, allowing attackers with manager or admin roles to write files to arbitrary locations on the server.\n\n- 📅 **Published:** 10/02/2025\n- 📈 **CVSS:** 7.2\n- 🧭 **Vector:** CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 5\n- ⚠️ **Priority:** 2\n\n---\n\n**8. [CVE-2025-42599](https://nvd.nist.gov/vuln/detail/CVE-2025-42599)**\n\n- 📝 Active! mail 6 BuildInfo: 6.60.05008561 and earlier contains a stack-based buffer overflow vulnerability. Receiving a specially crafted request created and sent by a remote unauthenticated attacker may lead to arbitrary code execution and/or a denial-of-service (DoS) condition.\n\n- 📅 **Published:** 18/04/2025\n- 📈 **CVSS:** 9.8\n- 🧭 **Vector:** CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 6\n- ⚠️ **Priority:** 4\n\n---\n\n**9. [CVE-2025-32433](https://nvd.nist.gov/vuln/detail/CVE-2025-32433)**\n\n- 📝 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 10\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n- 📣 **Mentions:** 44\n- ⚠️ **Priority:** 2\n\n---\n\n**10. [CVE-2025-24054](https://nvd.nist.gov/vuln/detail/CVE-2025-24054)**\n\n- 📝 NTLM Hash Disclosure Spoofing Vulnerability\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C\n- 📣 **Mentions:** 36\n- ⚠️ **Priority:** 1+\n\n---\n\nLet us know if you're tracking any of these or if you find any issues with the provided details, priority scores come from [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer).",
    "permalink": "/r/CVEWatch/comments/1k3shfh/top_10_trending_cves_20042025/",
    "timestamp": "2025-04-20T18:00:18",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-31201",
      "CVE-2025-31200"
    ],
    "cve_counts": {
      "CVE-2025-31200": 1,
      "CVE-2025-31201": 1
    },
    "title": "Alert to Apple Users on CoreAudio & RPAC",
    "text": "Apple has urged users to immediately update their devices following the discovery of two zero-day vulnerabilities exploited in what it called an “extremely sophisticated attack.” These bugs—found in CoreAudio and RPAC—allowed attackers to execute malicious code and bypass key security protections on targeted iPhones.\n\nThe vulnerabilities, CVE-2025-31200 and CVE-2025-31201, could lead to memory corruption, surveillance, or even kernel-level compromise. The threat actors behind these attacks seem to have used advanced methods aimed at specific individuals—making this a high-risk situation for Apple device owners.\n\nApple has now issued security patches across all affected platforms, including iOS, iPadOS, macOS, tvOS, and visionOS. Devices ranging from iPhone XS to the latest iPads are impacted, showing just how widespread the risk is.\n\nThis marks the fifth zero-day patch Apple has had to push in just four months—highlighting the relentless pace of vulnerability discovery and the increasing sophistication of cyber threats. Users and businesses alike should prioritise security hygiene more than ever.\n\nRead more here: https://www.csoonline.com/article/3964668/hackers-target-apple-users-in-an-extremely-sophisticated-attack.html \n\n",
    "permalink": "/r/u_cyberkite1/comments/1k3x2mm/alert_to_apple_users_on_coreaudio_rpac/",
    "timestamp": "2025-04-20T21:31:43",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3827"
    ],
    "cve_counts": {
      "CVE-2025-3827": 1
    },
    "title": "CVE Alert: CVE-2025-3827",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k44vpl/cve_alert_cve20253827/",
    "timestamp": "2025-04-21T04:16:22",
    "article_text": "A vulnerability has been found in PHPGurukul Men Salon Management System 1.0 and classified as critical. This vulnerability affects unknown code of the file /admin/forgot-password.php. The manipulation of the argument email leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-43928"
    ],
    "cve_counts": {
      "CVE-2025-43928": 1
    },
    "title": "CVE Alert: CVE-2025-43928",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k497cv/cve_alert_cve202543928/",
    "timestamp": "2025-04-21T09:16:23",
    "article_text": "In Infodraw Media Relay Service (MRS) 7.1.0.0, the MRS web server (on port 12654) allows reading arbitrary files via ../ directory traversal in the username field. Reading ServerParameters.xml may reveal administrator credentials in cleartext or with MD5 hashing.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-25364"
    ],
    "cve_counts": {
      "CVE-2025-25364": 1
    },
    "title": "\"Speedify VPN macOS\" pažeidžiamumas",
    "text": "\"Speedify VPN\" \"MacOS\" programoje aptikta reikšminga saugumo spraga, pažymėta kaip CVE-2025-25364, dėl kurios naudotojai gali padidinti vietines privilegijas ir visiškai sukompromituoti sistemą.  Ši spraga, kurią atskleidė \"SecureLayer7\", yra privilegijuotoje pagalbinėje priemonėje me.connectify.SMJobBlessHelper, kuri yra atsakinga už \"Speedify VPN\" kliento sistemos lygmens operacijų vykdymą su root privilegijomis.\n\nSkaitom: [https://cybersecuritynews.com/speedify-vpn-macos-vulnerability/](https://cybersecuritynews.com/speedify-vpn-macos-vulnerability/)",
    "permalink": "/r/KibernetinisSaugumas/comments/1k4bm78/speedify_vpn_macos_pažeidžiamumas/",
    "timestamp": "2025-04-21T11:52:31",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-31201",
      "CVE-2025-42599",
      "CVE-2025-0108",
      "CVE-2025-31200",
      "CVE-2025-27889",
      "CVE-2025-32434",
      "CVE-2025-2492",
      "CVE-2025-24054",
      "CVE-2024-10095",
      "CVE-2025-24071"
    ],
    "cve_counts": {
      "CVE-2025-31201": 2,
      "CVE-2025-2492": 2,
      "CVE-2025-31200": 2,
      "CVE-2025-24071": 2,
      "CVE-2025-0108": 2,
      "CVE-2025-32434": 2,
      "CVE-2024-10095": 2,
      "CVE-2025-42599": 2,
      "CVE-2025-27889": 2,
      "CVE-2025-24054": 2
    },
    "title": "🔥 Top 10 Trending CVEs (21/04/2025)",
    "text": "Here’s a quick breakdown of the 10 most interesting vulnerabilities trending today:\n\n**1. [CVE-2025-31201](https://nvd.nist.gov/vuln/detail/CVE-2025-31201)**\n\n- 📝 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 6.8\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N\n- 📣 **Mentions:** 24\n- ⚠️ **Priority:** 1+\n\n---\n\n**2. [CVE-2025-2492](https://nvd.nist.gov/vuln/detail/CVE-2025-2492)**\n\n- 📝 An improper authentication control vulnerability exists in AiCloud. This vulnerability can be triggered by a crafted request, potentially leading to unauthorized execution of functions. Refer to the ASUS Router AiCloud vulnerability section on the ASUS Security Advisory for more information.\n\n- 📅 **Published:** 18/04/2025\n- 📈 **CVSS:** 9.2\n- 🧭 **Vector:** CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N\n- 📣 **Mentions:** 15\n- ⚠️ **Priority:** 0\n\n---\n\n**3. [CVE-2025-31200](https://nvd.nist.gov/vuln/detail/CVE-2025-31200)**\n\n- 📝 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.\n\n- 📅 **Published:** 16/04/2025\n- 📈 **CVSS:** 7.5\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 31\n- ⚠️ **Priority:** 1+\n\n---\n\n**4. [CVE-2025-24071](https://nvd.nist.gov/vuln/detail/CVE-2025-24071)**\n\n- 📝 Microsoft Windows File Explorer Spoofing Vulnerability\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C\n- 📣 **Mentions:** 19\n- ⚠️ **Priority:** 2\n\n---\n\n**5. [CVE-2025-0108](https://nvd.nist.gov/vuln/detail/CVE-2025-0108)**\n\n- 📝 An authentication bypass in the Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to bypass the authentication otherwise required by the PAN-OS management web interface and invoke certain PHP scripts. While invoking these PHP scripts does not enable remote code execution, it can negatively impact integrity and confidentiality of PAN-OS. You can greatly reduce the risk of this issue by restricting access to the management web interface to only trusted internal IP addresses according to our recommended  best practices deployment guidelines https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431 . This issue does not affect Cloud NGFW or Prisma Access software.\n\n- 📅 **Published:** 12/02/2025\n- 📈 **CVSS:** 8.8\n- 🧭 **Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/AU:N/R:U/V:C/RE:M/U:Red\n- 📣 **Mentions:** 225\n- ⚠️ **Priority:** 2\n\n---\n\n**6. [CVE-2025-32434](https://nvd.nist.gov/vuln/detail/CVE-2025-32434)**\n\n- 📝 PyTorch is a Python package that provides tensor computation with strong GPU acceleration and deep neural networks built on a tape-based autograd system. In version 2.5.1 and prior, a Remote Command Execution (RCE) vulnerability exists in PyTorch when loading a model using torch.load with weights_only=True. This issue has been patched in version 2.6.0.\n\n- 📅 **Published:** 18/04/2025\n- 📈 **CVSS:** 9.3\n- 🧭 **Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N\n- 📣 **Mentions:** 6\n- ⚠️ **Priority:** 4\n\n---\n\n**7. [CVE-2024-10095](https://nvd.nist.gov/vuln/detail/CVE-2024-10095)**\n\n- 📝 In Progress Telerik UI for WPF versions prior to 2024 Q4 (2024.4.1213), a code execution attack is possible through an insecure deserialization vulnerability.\n\n- 📅 **Published:** 16/12/2024\n- 📈 **CVSS:** 8.4\n- 🧭 **Vector:** CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n- ⚠️ **Priority:** 2\n\n---\n\n**8. [CVE-2025-42599](https://nvd.nist.gov/vuln/detail/CVE-2025-42599)**\n\n- 📝 Active! mail 6 BuildInfo: 6.60.05008561 and earlier contains a stack-based buffer overflow vulnerability. Receiving a specially crafted request created and sent by a remote unauthenticated attacker may lead to arbitrary code execution and/or a denial-of-service (DoS) condition.\n\n- 📅 **Published:** 18/04/2025\n- 📈 **CVSS:** 9.8\n- 🧭 **Vector:** CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n- 📣 **Mentions:** 6\n- ⚠️ **Priority:** 4\n\n---\n\n**9. [CVE-2025-27889](https://nvd.nist.gov/vuln/detail/CVE-2025-27889)**\n\n- 📝 Mod Note: Not a lot of details on this one, picked up by the algorith based on social media mentions and posts on different security blogs, I will update it as soon as the information becomes available.\n- 📈 **CVSS:** 0\n- 🧭 **Vector:** n/a\n- ⚠️ **Priority:** n/a\n\n---\n\n**10. [CVE-2025-24054](https://nvd.nist.gov/vuln/detail/CVE-2025-24054)**\n\n- 📝 NTLM Hash Disclosure Spoofing Vulnerability\n\n- 📅 **Published:** 11/03/2025\n- 📈 **CVSS:** 6.5\n- 🛡️ **CISA KEV:** True\n- 🧭 **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C\n- 📣 **Mentions:** 36\n- ⚠️ **Priority:** 1+\n\n---\n\nLet us know if you're tracking any of these or if you find any issues with the provided details, priority scores come from [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer).",
    "permalink": "/r/CVEWatch/comments/1k4gvcl/top_10_trending_cves_21042025/",
    "timestamp": "2025-04-21T15:57:39",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-20236"
    ],
    "cve_counts": {
      "CVE-2025-20236": 1
    },
    "title": "Cisco Webex App Client-Side Remote Code Execution Vulnerability (CVE-2025-20236)",
    "text": "",
    "permalink": "/r/systemtek/comments/1k4g6cl/cisco_webex_app_clientside_remote_code_execution/",
    "timestamp": "2025-04-21T15:21:18",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-32434"
    ],
    "cve_counts": {
      "CVE-2025-32434": 2
    },
    "title": "Critical PyTorch Vulnerability Lets Attackers Run Malicious Code",
    "text": "\n**A serious vulnerability in PyTorch allows attackers to execute remote code, even when using previously recommended security measures.**\n\n**Key Points:**\n\n- CVE-2025-32434 affects all PyTorch versions up to 2.5.1.\n- Vulnerability exists in the torch.load function with weights_only=True parameter.\n- Remote code execution can happen without user interaction, posing significant risks.\n\nThe recently identified CVE-2025-32434 vulnerability in PyTorch is alarming for developers and organizations relying on machine learning frameworks. Discovered by researcher Ji'an Zhou, this security flaw enables remote code execution (RCE) when using the torch.load function with the weights_only=True parameter—a combination formerly recommended as a safe option for loading models. This contradiction in guidance puts many users at risk, as the vulnerability allows attackers to craft malicious model files that can execute arbitrary code on victim systems, potentially leading to catastrophic security breaches.\n\nThe impact of this vulnerability is particularly stark for machine learning pipelines that automatically download models from external sources or collaborative environments. With a CVSS score of 9.3, this critical vulnerability highlights how even established security measures can have unanticipated flaws. Users are urged to update to PyTorch version 2.6.0 or later to mitigate the risks or, as an interim measure, avoid using torch.load with weights_only=True. The incident underscores the importance of maintaining up-to-date dependencies in any production environment dealing with sensitive data, reminding organizations that vulnerabilities can lurk even in features designed to enhance security.\n\nHow can organizations better safeguard their machine learning pipelines against such vulnerabilities?\n\n**Learn More:** [Cyber Security News](https://cybersecuritynews.com/critical-pytorch-vulnerability/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k4ie8l/critical_pytorch_vulnerability_lets_attackers_run/",
    "timestamp": "2025-04-21T16:57:05",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-25364"
    ],
    "cve_counts": {
      "CVE-2025-25364": 2
    },
    "title": "Critical Speedify VPN Flaw Exposes macOS Users to Attacks",
    "text": "\n**A serious vulnerability in Speedify VPN for macOS allows local attackers to escalate privileges and gain control over systems.**\n\n**Key Points:**\n\n- CVE-2025-25364 allows local privilege escalation on Speedify VPN for macOS.\n- The vulnerability is caused by improper input handling in the helper tool.\n- Exploiting the flaw can lead to arbitrary command execution as root.\n- Speedify VPN has released an update addressing this critical security issue.\n- Users must upgrade to version 15.4.1 or higher to ensure their systems are protected.\n\nThe discovered vulnerability, tracked as CVE-2025-25364, is a significant security risk for users of Speedify VPN's macOS application. It resides in the me.connectify.SMJobBlessHelper helper tool, which executes system-level operations with root privileges. The security flaw arises from improper input validation in the XPC interface of this tool, allowing local attackers to inject malicious commands that the system would execute with root privileges.\n\nSpecifically, the commands can be injected through two user-controlled fields in incoming XPC messages, cmdPath and cmdBin, which are not adequately sanitized. Successful exploitation of this vulnerability can lead to local privilege escalation, allowing attackers not only to execute arbitrary commands but also to read, modify, or delete critical system files, and potentially install persistent malware. Speedify has responded to the issue with an updated version (15.4.1) that includes a complete rewrite of the flawed helper tool, eliminating the insecure handling of XPC messages and thereby closing this exploit vector. Users are strongly encouraged to update to the latest version to protect their devices from potential exploitation.\n\nWhat steps are you taking to ensure your VPN software is secure against vulnerabilities?\n\n**Learn More:** [Cyber Security News](https://cybersecuritynews.com/speedify-vpn-macos-vulnerability/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k4id8h/critical_speedify_vpn_flaw_exposes_macos_users_to/",
    "timestamp": "2025-04-21T16:55:59",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-25364"
    ],
    "cve_counts": {
      "CVE-2025-25364": 2
    },
    "title": "Critical Speedify VPN Flaw Exposes macOS Users to Attacks",
    "text": "\n**A serious vulnerability in Speedify VPN for macOS allows local attackers to escalate privileges and gain control over systems.**\n\n**Key Points:**\n\n- CVE-2025-25364 allows local privilege escalation on Speedify VPN for macOS.\n- The vulnerability is caused by improper input handling in the helper tool.\n- Exploiting the flaw can lead to arbitrary command execution as root.\n- Speedify VPN has released an update addressing this critical security issue.\n- Users must upgrade to version 15.4.1 or higher to ensure their systems are protected.\n\nThe discovered vulnerability, tracked as CVE-2025-25364, is a significant security risk for users of Speedify VPN's macOS application. It resides in the me.connectify.SMJobBlessHelper helper tool, which executes system-level operations with root privileges. The security flaw arises from improper input validation in the XPC interface of this tool, allowing local attackers to inject malicious commands that the system would execute with root privileges.\n\nSpecifically, the commands can be injected through two user-controlled fields in incoming XPC messages, cmdPath and cmdBin, which are not adequately sanitized. Successful exploitation of this vulnerability can lead to local privilege escalation, allowing attackers not only to execute arbitrary commands but also to read, modify, or delete critical system files, and potentially install persistent malware. Speedify has responded to the issue with an updated version (15.4.1) that includes a complete rewrite of the flawed helper tool, eliminating the insecure handling of XPC messages and thereby closing this exploit vector. Users are strongly encouraged to update to the latest version to protect their devices from potential exploitation.\n\nWhat steps are you taking to ensure your VPN software is secure against vulnerabilities?\n\n**Learn More:** [Cyber Security News](https://cybersecuritynews.com/speedify-vpn-macos-vulnerability/)\n\n**Want to stay updated on the latest cyber threats?** \n\n 👉 **[Subscribe to /r/PwnHub](https://www.reddit.com/r/pwnhub)**",
    "permalink": "/r/pwnhub/comments/1k4iaeb/critical_speedify_vpn_flaw_exposes_macos_users_to/",
    "timestamp": "2025-04-21T16:52:58",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "**Welcome to r/pwnhub – Your hub for hacking news, breach reports, and cyber mayhem.**  \n\nStay updated on **zero-days, exploits, hacker tools, and the latest cybersecurity drama**.  \n\nWhether you’re **red team, blue team, or just here for the chaos**—dive in and stay ahead.  \n\nStay sharp. Stay secure.  \n\n**[Subscribe and join us for daily posts!](https://www.reddit.com/r/pwnhub/)**\n\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/pwnhub) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2024-10914",
      "CVE-2024-41713",
      "CVE-2025-0108"
    ],
    "cve_counts": {
      "CVE-2025-0108": 1,
      "CVE-2024-41713": 1,
      "CVE-2024-10914": 1
    },
    "title": "Proton66 Bulletproof Hosting Used for Global Attacks",
    "text": "**Recent reports have exposed the abuse of Proton66, a Russian bulletproof hosting provider, by cybercriminals for mass scanning, brute-forcing, and malware delivery worldwide.** \n\nThe malicious activity, detected since January 2025, targets various vulnerabilities and attempts to exploit recent flaws like **CVE-2025-0108** (Palo Alto Networks PAN-OS), **CVE-2024-41713** (Mitel MiCollab), and **CVE-2024-10914** (D-Link NAS). The associated IP addresses have been linked to malware families like **XWorm**, **StrelaStealer**, and **WeaXor** ransomware.\n\n**Key Takeaways:**\n\n* **Proton66** has been linked to **GootLoader**, **SpyNote**, and new ransomware campaigns like **SuperBlack**.\n* Recent campaigns are exploiting CVEs, including the **Fortinet FortiOS** vulnerabilities, primarily attributed to the **Mora\\_001** threat actor.\n* Proton66 is also hosting **malicious JavaScript** to redirect Android users to phishing sites mimicking the Google Play Store.\n* **WeaXor** ransomware (a revision of Mallox) has been seen communicating with Proton66's infrastructure.\n\n**Actionable Intel:** Organizations should block all **Proton66**\\-related IP ranges (45.135.232.0/24, 45.140.17.0/24) to neutralize potential threats and avoid interaction with this bulletproof host.\n\n**Open for Discussion:**  \nWhat are your thoughts on the increasing trend of bulletproof hosting abuse and its role in the evolution of cybercrime? Have you seen similar tactics in your threat landscape?\n\nStay vigilant and share any related intel.",
    "permalink": "/r/DarkWireSys/comments/1k4ljco/proton66_bulletproof_hosting_used_for_global/",
    "timestamp": "2025-04-21T18:59:39",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2024-9142"
    ],
    "cve_counts": {
      "CVE-2024-9142": 2
    },
    "title": "CVE-2024-9142 – Windows SMB Compression PrivEsc (Unpatched)",
    "text": "**CVE-2024-9142** is flying under the radar—but it’s a potential SMBGhost sequel.\n\n➡️ Summary:\n\n* Exploits an overflow in Windows SMB compression when handling malformed NTFS filenames\n* Local user → SYSTEM via remote share and symlink abuse\n* No patch as of now, mitigations include disabling compression entirely\n\nProof-of-concept is being quietly traded on [Exploit.in](http://Exploit.in) and a few GitHub gists that come and go fast.\n\nCould be wormable with the right twist. Worth keeping an eye on.",
    "permalink": "/r/DarkWireSys/comments/1k4kpjs/cve20249142_windows_smb_compression_privesc/",
    "timestamp": "2025-04-21T18:26:59",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-3841"
    ],
    "cve_counts": {
      "CVE-2025-3841": 1
    },
    "title": "CVE Alert: CVE-2025-3841",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k4xkqo/cve_alert_cve20253841/",
    "timestamp": "2025-04-22T04:16:19",
    "article_text": "A vulnerability, which was classified as problematic, was found in wix-incubator jam up to e87a6fd85cf8fb5ff37b62b2d68f917219d07ae9. This affects an unknown part of the file jam.py of the component Jinja2 Template Handler. The manipulation of the argument config[‘template’] leads to improper neutralization of special elements used in a template engine. It is possible to launch the attack on the local host. The exploit has been disclosed to the public and may be used. This product takes the approach of rolling releases to provide continious delivery. Therefore, version details for affected and updated releases are not available.",
    "comments": []
  },
  {
    "cves": [
      "CVE-2023-40547"
    ],
    "cve_counts": {
      "CVE-2023-40547": 2
    },
    "title": "Question about shim and sbat policys in regards to vulnerability: CVE-2023-40547",
    "text": "Hello!\nI used to dualboot Ubuntu 24.02.4 LTS with Windows 11.\nDecided to completely remove Windows and was greeted with the ”Verifying shim SBAT data failed: Security Policy Violation”message.\n\nAfter disabling secureboot and reinstalling Ubuntu 24.02.2 LTS I was finally able to boot into linux again with secure boot enabled.\n\nNow to my question:\nAs I understand it, Microsoft released an update to mitigate the Shim vulnerability tracked as: CVE-2023-40547 which caused many Linux distros using the vulnerable Shim version to get blocked in Shims own revocations list.\n\nI have checked my current Shim version which reports version 15.8, so far so good. (As I understand it, this is the latest version).\nHowever, I seem to still be using an old Shim revocations list.\n\nCommand: mokutil —list-sbat-revocations gives me the following output:\n\nsbat,1,2023012900\nshim,2\ngrub,3\ngrub.debian,4\n\nHowever, Isn’t the new revocations list as follows:\n\nsbat,1,2024010900\nshim,4\ngrub,3\ngrub.debian,4\n\nHow do I update the shim revocations list to the latest version? Should that not be included in the latest shim version by default?",
    "permalink": "/r/linux4noobs/comments/1k504i8/question_about_shim_and_sbat_policys_in_regards/",
    "timestamp": "2025-04-22T07:01:34",
    "article_text": null,
    "comments": [
      {
        "score": 1,
        "text": "There's a [resources page](http://www.reddit.com/r/linux4noobs/wiki/faq) in our wiki you might find useful!\n\nTry [this search](https://www.reddit.com/r/linux4noobs/search?q=flair%3A'learning%2Fresearch'&sort=new&restrict_sr=on) for more information on this topic.\n\n**✻** Smokey says: take regular backups, try stuff in a VM, and understand every command *before* you press Enter! :)\n\n^Comments, ^questions ^or ^suggestions ^regarding ^this ^autoresponse? ^Please ^send ^them ^[here](https://www.reddit.com/message/compose/?to=Pi31415926&subject=autoresponse+tweaks+-+linux4noobs+-+research).\n\n*I am a bot, and this action was performed automatically. Please [contact the moderators of this subreddit](/message/compose/?to=/r/linux4noobs) if you have any questions or concerns.*",
        "level": 0
      }
    ]
  },
  {
    "cves": [
      "CVE-2025-30406"
    ],
    "cve_counts": {
      "CVE-2025-30406": 2
    },
    "title": "Gladinet Vulnerability Opening CenteStaack and Triofox.",
    "text": "On April 3, 2025, Gladinet disclosed a vulnerability, CVE-2025-30406 (CVSS 9.8), impacting CentreStack and Triofox servers.  \n\n \n\nThe vulnerability is a deserialization vulnerability due to the CentreStack and Triofox portal's hardcoded machineKey use. The vulnerability impacts Gladinet CentreStack through version 16.1.10296.56315 and TrioFox below version 16.4.10317.56372. \n\n \n\n**Is there active exploitation at the time of writing?**  \n\nAt the time of writing (April 21, 2025), Blackpoint’s SOC has observed exploitation of this vulnerability against versions of CentreStack, including some that are fully patched. There is an even chance the patch for CVE-2025-30406 is failing to automatically rotate machineKey’s, which leaves these applications vulnerable.  \n\n \n\nExploitation of this deserialization vulnerability provides a threat actor remote code execution against the host running CentraStack or Triofox. Threat actors are leveraging this remote execution to enumerate the targeted host and Active Directory Environment. After enumeration, the Blackpoint SOC has observed threat actors that utilize access to remotely execute malicious payloads in memory amongst the following:  \n\n* Read out /etc/hosts\n* Read out boot.ini\n* Read out configuration files\n* Enumerate domain computers, users, admins, trusts\n* Enumerate available shares\n* Enumerate current user and user’s role in domain\n* Enumerate network information\n* Enumerate running processes\n* Read out SAM Hive\n* Download and execute malicious stagers in memory \n\nThe vulnerability has been reported to be actively exploited since at least March 2025; the vulnerability was added to the U.S. CISA’s Known Exploited Vulnerabilities (KEV) Catalog on April 08, 2025. \n\n \n\n**Indicators observed:**  \n\n* portal.config\n* d27486c15c08cbd3ebe4de878995e4beae05f5f0824434a8bbf3a4c6362bf9a6\n* 92.119.197\\[.\\]3\n* c5ae011a.log.cdncache\\[.\\]rr\\[.\\]nu \n\n**Recommendations** \n\n* Immediate Action: Apply the latest CentreStack and Triofox server updates to ensure the vulnerability is patched; verify the machineKey was rotated.\n* If patching is not immediately available (or the patch did not rotate the machinekey), ensure to manually rotate the machineKey (Update machine Key). \n* Audit logs for indications of access, including logs for access to /portal/script endpoints.\n* Limit external access to CentreStack interfaces wherever possible.\n* Actively monitor for suspicious deserialization activities. ",
    "permalink": "/r/msp/comments/1k4zqm4/gladinet_vulnerability_opening_centestaack_and/",
    "timestamp": "2025-04-22T06:35:39",
    "article_text": null,
    "comments": []
  },
  {
    "cves": [
      "CVE-2025-29287"
    ],
    "cve_counts": {
      "CVE-2025-29287": 1
    },
    "title": "CVE Alert: CVE-2025-29287",
    "text": "",
    "permalink": "/r/RedPacketSecurity/comments/1k51xwh/cve_alert_cve202529287/",
    "timestamp": "2025-04-22T09:16:24",
    "article_text": "An arbitrary file upload vulnerability in the ueditor component of MCMS v5.4.3 allows attackers to execute arbitrary code via uploading a crafted file.",
    "comments": []
  }
]
