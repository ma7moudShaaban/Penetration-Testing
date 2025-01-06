# Attacking Domain Trusts
- [Overview](#overview)


## Overview
- A trust is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in (or perform administrative tasks) another domain, outside of the main domain where their account resides. A trust creates a link between the authentication systems of two domains and may allow either one-way or two-way (bidirectional) communication. An organization can create various types of trusts:
    1. Parent-child: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain corp.inlanefreight.local could authenticate into the parent domain inlanefreight.local, and vice-versa.
    2. Cross-link: A trust between child domains to speed up authentication.
    3. External: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering or filters out authentication requests (by SID) not from the trusted domain.
    4. Tree-root: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
    5. Forest: A transitive trust between two forest root domains.
    6. ESAE: A bastion forest used to manage Active Directory.