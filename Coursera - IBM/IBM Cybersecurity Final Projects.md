IBM

Course 1 - Introduction to Cybersecurity Careers - Final Assessment was an exam - Score 100%

Course 2 - Introduction to Cybersecurity Essentials - Final Assessment was an exam - Score 87%

Course 3 - Introduction to Cybersecurity Tools & Cyberattacks - Score 90%
    Final Project Overview: Secure Access
Overview
In this course, you learned the crucial skills to tackle modern, evolving digital threats and challenges. From threat detection to prevention strategies, you learned to safeguard your organizations and systems against data breaches. In this project, you will explore a real-world-inspired scenario, identify potential security vulnerabilities, and provide recommendations to strengthen the organization's overall security posture.
This final project comprises three tasks:
1.	Evaluate the organization's existing security infrastructure
2.	Create a multifactor authentication (MFA) plan
3.	Evaluate the organization's existing physical security measures
General instructions
The final project consists of three tasks, each containing two questions, contributing to a total of 15 points. Carefully read through the scenarios and the accompanying tasks. Then, critically analyze each question and provide well-considered responses to demonstrate your understanding and proficiency.
To complete this project, you must answer all the questions and submit the assignment as proof of completing the final project's requirements. You can pause and resume the submission process based on your schedule, giving you the flexibility to complete this project at your own pace. Your submission will be auto-graded using an AI tool.
Scenario for Task 1 and Task 2
You are an IT Security Analyst at TechSolutions Inc. The company has recently experienced a data breach due to compromised credentials.
TechSolutions Inc. currently employs the following security infrastructure:
•	The traditional access control methods include:
o	Username and password sign-in for each system and application.
o	SSH keys to access remote servers.
o	Smart cards for secure physical and digital access across multiple company locations and the corporate VPN.
•	The resources that employees require access to:
o	Corporate email system: Essential for day-to-day communication, both internally and with external stakeholders.
o	Internal databases: Contains sensitive information such as client details, project data, and financial records.
o	Cloud storage services: Used for storing and sharing documents and collaborative work.
o	HR systems: Incorporates personal information of employees, benefits administration, and recruitment data.
o	Customer relationship management (CRM) software: Critical for sales, marketing, and customer service operations.
o	Project management tools: Used for tracking progress, assigning tasks, and optimizing workflow.
o	Development environments: Required for software development, testing applications, and managing code repositories.
o	Company intranet and knowledge bases: Provides access to company policies, training materials, and internal communication platforms.
Task 1 Instructions
This task comprises two questions and carries 6 points. Thoroughly review the scenario above and answer the questions.
Review the security infrastructure currently deployed at TechSolutions Inc. This task will require you to leverage your understanding of cybersecurity principles and apply critical thinking to assess and enhance the security infrastructure of TechSolutions Inc.

Question 1:
List three potential security concerns within the existing security framework, particularly focusing on areas that could have contributed to the compromise of credentials.

Response:
Given the recent data breach, here are three high-priority security concerns within TechSolutions Inc.'s existing framework that likely contributed to the credential compromise:
1. Excessive Reliance on Single-Factor Authentication (SFA)
The core problem is the "Username and password sign-in for each system and application." This is Single-Factor Authentication (SFA) and is the lowest security standard.
•	Concern: Passwords are highly susceptible to phishing, keylogging malware, and guessing.
•	Contribution: The lack of a secondary verification factor means that an attacker who compromises one password gains full, immediate access. If employees reuse passwords across systems, one successful attack grants an attacker access to multiple high-value resources (e.g., Internal Databases, HR Systems).
2. Distributed and Fragmented Credential Management
The setup requires separate management of username/password pairs, SSH keys, and smart cards.
•	Concern: This fragmented approach is confusing for employees, leading to "password fatigue."
•	Contribution: Employees often cope by choosing weak or easily guessable passwords or reusing them, which enables credential stuffing attacks. The complexity of managing unique SSH keys for servers also increases the likelihood of human error or insecure storage.
3. High-Value, Single-Point-of-Failure Smart Cards
While a step up, the smart cards are a high-value target because they secure the Corporate VPN and physical access.
•	Concern: If the smart card's associated PIN/password is phished, or the physical card is stolen along with an insecurely stored PIN, the attacker gains access to a critical, high-privilege gateway (the VPN) that bypasses network perimeter defenses.
•	Contribution: Compromise of this single token grants the attacker a broad, trusted foothold on the internal network.
Question 2:
Provide a high-level solution (less then 25 words) for each of the three identified security concerns above. limit the total response to a maximum of 500 words.
Response:
1. Excessive Reliance on Single-Factor Authentication (SFA)
High-Level Solution: Implement Multi-Factor Authentication (MFA) across all systems, especially for email, databases, and the VPN. 
•	Detail: Enforce MFA for every employee login to significantly increase the difficulty for an attacker. Even if a password is compromised via phishing, the attacker cannot gain access without the second factor (e.g., a time-based one-time password (TOTP) from an authenticator app or a security key). This is the single most effective defense against credential theft.
2. Distributed and Fragmented Credential Management
High-Level Solution: Adopt Single Sign-On (SSO), integrate with an Identity Provider (IdP), and centralize SSH key management. 
•	Detail: Implement an SSO solution to allow employees to use one set of strong credentials to access all corporate resources (Email, CRM, Cloud Storage, HR Systems). This eliminates the need for dozens of individual passwords, reducing password fatigue and the incentive for reuse. Centralize the management and rotation of SSH keys using an Identity and Access Management (IAM) platform to reduce the risk of unmanaged, persistent key access.
3. High-Value, Single-Point-of-Failure Smart Cards
High-Level Solution: Pair smart card access with biometric checks or a second MFA method; strictly enforce PIN rotation/complexity. 
•	Detail: While smart cards are a form of MFA ("something you have"), their vulnerability increases if the associated PIN ("something you know") is compromised. For high-privilege access, such as the corporate VPN or sensitive locations, enforce the use of a second, independent factor (e.g., a biometric scan or a unique, time-sensitive code). Furthermore, implement strict policies to ensure smart card PINs are complex, unique, and rotated regularly, and never stored near the physical card.
Task 2 instructions
This task includes two questions with a total value of 3 points.
Consider the various authentication methods you learned in this course. Your task is to revamp the access control system at TechSolutions Inc. by incorporating multifactor authentication (MFA) to safeguard against future unauthorized access.

Question 3 & 4
Explain how the two authentication factors will work together to create a Multi-Factor Authentication (MFA) plan for TechSolutions Inc. 
methods:
PIN + Hardware Security Key

Response:
The two factors—a PIN and a Hardware Security Key—create a highly secure Multi-Factor Authentication (MFA) plan for TechSolutions Inc. by requiring credentials from two distinct categories: something you know and something you have. This combination is highly effective against remote cyberattacks like phishing.
MFA Factor Combination 
•	PIN (Something You Know): This is a short, secret numeric code that the user memorizes. Its primary function in this MFA plan is not to verify the user to the network, but to unlock and activate the private cryptographic key stored inside the hardware device.
•	Hardware Security Key (Something You Have): This is a physical, un-copyable device (e.g., a FIDO2 token) that contains the user’s cryptographic signing key. It provides the possession factor.
The Access Workflow 
The two factors work together in a cascading, two-step verification process to grant access:
1.	Possession Verification (The Key): The user first inserts or taps the Hardware Security Key into their device (USB or NFC). The system detects the physical presence of the key, satisfying the "something you have" requirement.
2.	Knowledge Verification (The PIN): The system then prompts the user for the unique PIN. Only when the correct PIN is entered is the hardware key authorized to perform its function—which is to cryptographically sign the unique login challenge sent by the server.
This sequence ensures that a lost or stolen key is useless without the user's secret PIN, and a compromised PIN is useless without the physical key.
Core Security Benefit
This method offers phishing resistance because the key's cryptographic signature is tied to the genuine website's domain. Even if an attacker captures the PIN and key prompt through a fake site, the key will refuse to authenticate to the wrong domain, preventing account takeover.

Scenario for Task 3
TechSolutions Inc. currently employs the following physical security measures:
•	Reception and lobby: The entrance features a reception desk that is always manned. The receptionist takes the names of each visitor and issues temporary visitor badges.
•	Employee workspaces: The open-plan workspaces for employees are accessible from two directions. One entrance, located near the receptionist's desk, leads to the front of the workspace area, while another door at the back opens into the employee parking lot. Both entrances are clearly marked with signs reading "Authorized Personnel Only." The receptionist locks the front door, and the last person leaving for the day locks the back door.
•	Meeting rooms and conference halls: Larger meeting spaces are adjacent to the shared workspace. Each of these spaces has doors that can be locked. Reservations for these spaces can be made through a central calendar system.
•	Data centers and server rooms: These critical areas are equipped with lockable doors, with access restricted to the IT and janitorial staff. Additionally, these rooms are fitted with a thermostat and humidity sensor for monitoring purposes.
•	File storage: File cabinets with locking mechanisms are strategically located throughout the office space to ensure sensitive documents are secure and accessible only by authorized personnel.
•	Parking lot: The employee parking lot is enclosed by a fence with only one entry point. Parking stickers are required to access this parking lot.
•	Common areas and facilities: Breakrooms and restrooms are adjacent to the common work area. The doors leading to these areas do not have locks.
Task 3 Instructions
This task consists of two questions totaling 6 points. Thoroughly review the scenario and answer the questions.
Review the physical security measures currently deployed at TechSolutions Inc. This task will require you to leverage your understanding of cybersecurity principles and apply critical thinking to assess and enhance the physical security measures at TechSolutions Inc.

Question 4:
Provide one recommendation for each of the three identified physical security vulnerabilities.  These recommendations must be practical, address the concern effectively, and suggest a clear path for remediation or improvement.

Response:
Here are practical recommendations for the three identified physical security vulnerabilities at TechSolutions Inc.:
1. Vulnerability: Manual Door Security
Recommendation: Install Electronic Access Control on Both Workspace Doors.
Replace the manual locks on both the front and back workspace doors with an electronic access control system (e.g., key card or badge readers). This system should be programmed to automatically secure and lock the doors outside of business hours, eliminating reliance on the last person leaving. This provides a verifiable audit trail of all after-hours entries, significantly improving accountability and security.
2. Vulnerability: Parking Lot Entry Controlled by Stickers
Recommendation: Implement an Automated Gate with RFID Access Control.
Install a security gate arm (boom barrier) at the parking lot's single entry point. Control this barrier using long-range RFID readers that scan a dedicated tag affixed to an authorized vehicle. This is a vast improvement over static stickers, as it provides a physical barrier and allows for immediate deactivation of lost or terminated employee tags, ensuring only authorized vehicles can enter.
3. Vulnerability: Janitorial Staff Access to Data Centers
Recommendation: Establish an Escort-Only Policy for Janitorial Access.
Remove all standard access (keys/cards) for the janitorial staff to the data center and server rooms. Implement a formal policy that requires janitorial services to be coordinated and escorted by an authorized member of the IT staff at all times. This simple measure mitigates the risk of accidental damage or insider threat by ensuring critical equipment is never unsupervised during cleaning or maintenance.

Course 4 - Operating Systems Overview Administration Security - Score 93%
Final Project Shareable link - https://www.coursera.org/learn/operating-systems-overview-administration-security/peer/Nmgjz/peer-review/review/1toG6LN6EfCpJwr_w5gUgQ

Course 5 - Network Security Databases Vulnerabilities - Score 94%
Final Project Shareable link - https://www.coursera.org/learn/network-security-database-vulnerabilities/peer/PewIp/peer-graded-final-assignment/review/gS7Ay8uxEfCBmwr_5ctvjQ

Course 6 - 

Course 7 -

Course 8 - 

Course 9 -

Course 10 -
 
Course 11 - 

Course 12 -

Course 13 -

Course 14 -

