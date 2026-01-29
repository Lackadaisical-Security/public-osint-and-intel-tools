# Code of Conduct

## Philosophy

Public OSINT & Intelligence Gathering Tools is built on **technical excellence, meritocracy, and operational security**. This project operates under old-school hacker ethics from the leet era: your code speaks louder than anything else. If you can contribute quality OSINT tools, prove your security expertise, and operate with integrity, you're in.

**No politics. No bullshit. Just intelligence gathering.**

## Core Principles

### 1. Merit is King
- **Your contributions are judged by technical merit only** - tool accuracy, code quality, reproducibility, operational security
- Skill level doesn't matter if you're willing to learn and improve
- Show your work. Explain your methodology. Defend your techniques with results
- If your tool produces false positives, explain why or fix it

### 2. Technical Competence Over Everything
- Know what you're talking about or shut up
- Understand the techniques behind your OSINT tools
- Research before you ask questions - read the docs, check existing tools
- "My script doesn't work" is not a bug report - show error logs, request/response data, debug output
- If you claim a tool works, provide test cases and verification

### 3. Intellectual Honesty
- Don't plagiarize tools or code. Cite your sources
- If you don't know something, say so - nobody expects you to know every OSINT technique
- Admit when your tool has limitations or edge cases
- Document your methods honestly - include failed attempts and lessons learned
- Cherry-picking results is bullshit - report all relevant findings

### 4. Hacker Ethics (Classic)
- **Access to information should be unlimited and total** - but you better have authorization to gather it
- **All tools should be open** - but stealing API keys isn't "liberation," it's theft
- **Mistrust authority – promote transparency** - verify every piece of intelligence
- **You can create intelligence with code** - make elegant tools, not bloated garbage
- **OSINT can change the world for the better** - build tools that actually solve problems

## What We Expect

### Technical Standards
- Write clean, documented, reproducible code
- Follow PEP 8 style for Python (use `black`, `flake8`, `mypy`)
- Provide working examples with sample data
- Security matters - don't leak credentials, use proper encryption, respect privacy
- Performance matters - optimize API calls, don't waste resources

### Communication Standards
- Be direct and honest - no passive-aggressive nonsense
- Technical criticism is not personal - "your tool sucks" means improve the implementation
- If someone's code is inefficient, explain WHY and HOW to fix it
- Argue about techniques, methodologies, and implementations - not personalities
- Keep discussions on-topic and focused on the tools

### Collaboration Standards
- Review others' code honestly - don't approve broken tools
- Respond to feedback constructively - defend your approach with evidence
- Share knowledge when asked - the community grows when experts teach
- If you promise to deliver a tool, deliver it or say you can't
- Open-source your best work - don't hoard knowledge

## What We Don't Tolerate

### Hard Bans (Instant Removal)
- **Using tools for unauthorized surveillance/hacking** - we're not covering your ass in court
- **Gathering intelligence without authorization** - respect legal boundaries
- **Doxxing, harassment, or stalking** - this is an OSINT research project, not a harassment platform
- **Stealing API keys and claiming them as your own** - plagiarism is for script kiddies
- **Deliberately introducing backdoors into tools** - you'll be reported to authorities
- **Violating privacy laws (GDPR, CCPA, etc.)** - read SECURITY.md and PRIVACY.md
- **Exporting tools to sanctioned countries** - respect export controls

### Soft Bans (Warning → Kick)
- Repeatedly submitting tools with no documentation
- Arguing without evidence ("I think this tool is better" - cool, show the benchmarks)
- Not following contribution guidelines after being told multiple times
- Wasting maintainers' time with questions covered in documentation
- Using tools on targets without proper authorization

### What's NOT a Violation
- Using "offensive" language in technical discussions - we're adults
- Disagreeing strongly with implementation choices - if you have a better one, prove it
- Calling out poorly written tools - that's literally what code review is for
- Being blunt or direct - we value efficiency over hand-holding
- Memes, jokes, and security culture references - this is part of the tradition
- Healthy skepticism of tool claims - "pics or it didn't happen" applies to OSINT results

## Legal & Ethical Use

### Authorized Use Requirements
This is not negotiable. **You MUST:**
- Obtain **written authorization** before using tools for security assessments
- Comply with all applicable laws (GDPR, CCPA, ECPA, CFAA, export controls)
- Respect data privacy - don't gather PII without consent
- Follow responsible disclosure practices
- Disclose tool capabilities and limitations to stakeholders

### Prohibited Activities
You will be banned and potentially reported if you:
- Use tools for unauthorized surveillance or monitoring
- Conduct cyber espionage or state-sponsored hacking
- Gather intelligence from stolen datasets or unauthorized sources
- Export tools to sanctioned countries (Cuba, Iran, North Korea, Syria, Russia, Belarus)
- Violate export control laws
- Create tools for harassment or stalking
- Use tools to violate human rights

**If you get arrested for doing dumb shit with these tools, you're on your own.**

## OSINT-Specific Ethics

### Privacy and Consent
- **Respect privacy boundaries** - Just because information is public doesn't mean it should be gathered
- **Data minimization** - Don't collect more data than necessary
- **Responsible disclosure** - Report security issues properly
- **Consent matters** - Get authorization before investigating individuals

### Accuracy and Verification
- **Verify intelligence** - Cross-reference sources, validate findings
- **Document confidence levels** - Be clear about certainty of intelligence
- **Avoid assumptions** - Don't fill gaps with speculation
- **Report failures** - Document when tools fail or produce false positives

### Operational Security
- **Protect sources and methods** - Don't expose intelligence gathering techniques unnecessarily
- **Use anonymization** - Leverage Tor, VPNs, proxies when appropriate
- **Secure credentials** - Use encrypted credential storage
- **Clean operational data** - Don't leave traces that compromise operations

### Dual-Use Concerns
These tools are designed for security and intelligence gathering - they have legitimate and illegitimate uses:

**Legitimate:**
- Authorized security assessments
- Threat intelligence gathering
- Digital forensics investigations
- Competitive intelligence (within legal bounds)
- Personal privacy audits
- Academic research

**Illegitimate:**
- Unauthorized surveillance
- Stalking or harassment
- Corporate espionage without authorization
- State surveillance without warrants
- Human rights violations
- Privacy law violations

**Use responsibly or don't use at all.**

## Enforcement

### Who Enforces
Project maintainer (Lackadaisical Security) has final say. This is not a democracy.

### How to Report Issues
- **Tool bugs**: Open a GitHub issue with full reproduction (code, logs, environment)
- **Security vulnerabilities**: Email lackadaisicalresearch@pm.me (PGP preferred)
- **Privacy/ethical concerns**: Email with evidence and analysis
- **Code of conduct violations**: Email lackadaisicalresearch@pm.me with evidence
- **Illegal use of tools**: Report to appropriate law enforcement, cc us if relevant

### Consequences
1. **First offense**: Warning via email/issue comment - fix the problem
2. **Second offense**: Temporary ban (duration depends on severity)
3. **Third offense / Severe violations**: Permanent ban from project
4. **Criminal activity**: Reported to authorities, permanent ban, legal action if applicable

### Appeals
If you think you were banned unfairly, email with a technical/evidence-driven explanation. If you can't defend your position with facts, the ban stands.

## Attribution

This Code of Conduct is **NOT** based on Contributor Covenant or any corporate template.

This is based on:
- **Hacker Ethic** (Steven Levy, 1984)
- **OSINT Community Standards** (SANS, OPSEC practices)
- **Old-school open source** (Linux kernel, BSD culture)
- **Meritocratic principles** of technical communities
- **Responsible Intelligence Practices**

## Philosophy: Why This Approach?

Public OSINT & Intelligence Gathering Tools are **production-grade tools for security professionals**. The stakes are incredibly high:
- Tools can enable mass surveillance if misused
- Poor tools can lead to false intelligence and wrong conclusions
- Privacy violations can destroy lives
- Export control violations carry criminal penalties
- Legal violations can result in prosecution

**We need contributors who:**
- Take OSINT ethics seriously
- Can handle direct technical criticism
- Prioritize accuracy and verification
- Understand the legal and ethical implications
- Can defend their tools with evidence, not opinions

If you're looking for a "safe space" where your broken tool gets praised, this isn't it. If you want to build cutting-edge OSINT tools with people who care about both capability and ethics, welcome aboard.

## Contact

**Maintainer**: Lackadaisical Security  
**Email**: lackadaisicalresearch@pm.me  
**XMPP+OTR**: thelackadaisicalone@xmpp.jp  
**Website**: https://lackadaisical-security.com  
**GitHub**: https://github.com/Lackadaisical-Security

---

**TL;DR**: Be competent. Be honest. Document your tools. Don't gather data without authorization. Don't deploy without permission. Capability and ethics both matter.

**Copyright © 2025-2026 Lackadaisical Security. All rights reserved.**
