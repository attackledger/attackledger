BEGIN TRANSACTION;
CREATE TABLE agent_exchanges (
	id INTEGER NOT NULL, 
	job_id INTEGER NOT NULL, 
	xid VARCHAR(16) NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	method VARCHAR(16) NOT NULL, 
	url TEXT NOT NULL, 
	status INTEGER NOT NULL, 
	redaction JSON, 
	created_at DATETIME NOT NULL, account VARCHAR(16), approval_id INTEGER, 
	PRIMARY KEY (id), 
	UNIQUE (job_id, xid), 
	FOREIGN KEY(job_id) REFERENCES jobs (id)
);
INSERT INTO "agent_exchanges" VALUES(1,3,'x1','1fdabc37846379faefd1a0dbb8020f6d8334efbd8cd780540b63f35b4270d64f','GET','https://shop.alpha.example.com/',200,'{"kinds": {}, "not_redacted": []}','2026-10-09 22:59:32.963776',NULL,NULL);
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO "alembic_version" VALUES('0021');
CREATE TABLE assets (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	host VARCHAR(255) NOT NULL, 
	in_scope BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	UNIQUE (engagement_id, host)
);
INSERT INTO "assets" VALUES(1,1,'shop.alpha.example.com',1);
CREATE TABLE audit_log (
	id INTEGER NOT NULL, 
	seq INTEGER NOT NULL, 
	at VARCHAR(40) NOT NULL, 
	actor_kind VARCHAR(16) NOT NULL, 
	actor_user_id INTEGER, 
	actor_name VARCHAR(200) NOT NULL, 
	actor_email VARCHAR(254), 
	action VARCHAR(40) NOT NULL, 
	engagement_id INTEGER, 
	subject_id INTEGER, 
	change TEXT NOT NULL, 
	record_sha256 VARCHAR(64) NOT NULL, 
	prev_hash VARCHAR(64) NOT NULL, 
	entry_hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (seq), 
	FOREIGN KEY(actor_user_id) REFERENCES users (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(subject_id) REFERENCES users (id)
);
INSERT INTO "audit_log" VALUES(1,1,'2026-10-09T22:59:32.679889+00:00','open',NULL,'open mode',NULL,'person.created',NULL,1,'{"after":{"disabled":false,"email":"owner-alpha@example.com","is_owner":true,"name":"Olive alpha"},"password":"assigned","person":{"email":"owner-alpha@example.com","id":1,"name":"Olive alpha"}}','99d728582ee961209dc70b37648c7e54223586cd10d4f1c741b36a7a2aa27226','0000000000000000000000000000000000000000000000000000000000000000','bdbbe65aa90b2d69831f4a17d41b3a82ad4ba1533f0a9a6f7f043ede028c15bd');
INSERT INTO "audit_log" VALUES(2,2,'2026-10-09T22:59:32.732642+00:00','person',1,'Olive alpha','owner-alpha@example.com','person.created',NULL,2,'{"after":{"disabled":false,"email":"reviewer-alpha@example.com","is_owner":false,"name":"Rita alpha"},"password":"assigned","person":{"email":"reviewer-alpha@example.com","id":2,"name":"Rita alpha"}}','8af9a58ff5e806f115d99bcbbfd477343e7f8a2d83ffc9e44f9fe0c91cbace0b','bdbbe65aa90b2d69831f4a17d41b3a82ad4ba1533f0a9a6f7f043ede028c15bd','161fbf582c4cdbc69fce9bcf9606b77c5eea7ffd15b3bea7113b2b25c0d487a3');
INSERT INTO "audit_log" VALUES(3,3,'2026-10-09T22:59:32.757481+00:00','person',1,'Olive alpha','owner-alpha@example.com','person.created',NULL,3,'{"after":{"disabled":false,"email":"viewer-alpha@example.com","is_owner":false,"name":"Vic alpha"},"password":"assigned","person":{"email":"viewer-alpha@example.com","id":3,"name":"Vic alpha"}}','b55abeca32ea887619300e030ebb09fcb25a80979a76005dccec586a1cc44156','161fbf582c4cdbc69fce9bcf9606b77c5eea7ffd15b3bea7113b2b25c0d487a3','84038cf810be6c53ffc65c7178663c0e04414a555fb94a9bc86025a8e28e3a77');
INSERT INTO "audit_log" VALUES(4,4,'2026-10-09T22:59:32.760847+00:00','person',1,'Olive alpha','owner-alpha@example.com','engagement.created',1,NULL,'{"after":{"engagement_type":"bug_bounty","name":"Engagement alpha","pack_id":"bug-bounty","policy_url":null}}','4f5e084a9b8f5926d248e50126f0ce5112b276d88ecbe62cbbf8001f955e96fe','84038cf810be6c53ffc65c7178663c0e04414a555fb94a9bc86025a8e28e3a77','2663b75f3096834e15fddfa3de6b21d7e77625120b22b28904b3f3b964f995af');
INSERT INTO "audit_log" VALUES(5,5,'2026-10-09T22:59:32.765678+00:00','person',1,'Olive alpha','owner-alpha@example.com','scope.updated',1,NULL,'{"after":{"crawl_depth":3,"enabled_modules":[],"exclude":[],"include":["*.alpha.example.com"],"rate_limit_rps":5,"research_header":"X-Bug-Bounty: alpha","research_user_agent":null},"before":{"crawl_depth":3,"enabled_modules":[],"exclude":[],"include":[],"rate_limit_rps":5,"research_header":null,"research_user_agent":null}}','24971373540d96c0a7485fff52fb0324e4f59bc7963519f4e4bf5920f2fbb7b3','2663b75f3096834e15fddfa3de6b21d7e77625120b22b28904b3f3b964f995af','0fdeee9f781dc74abf1ded8468d762baf29221bf1044c0fd883d511c32910e75');
INSERT INTO "audit_log" VALUES(6,6,'2026-10-09T22:59:32.768064+00:00','person',1,'Olive alpha','owner-alpha@example.com','engagement.authorized',1,NULL,'{"after":{"authorized_at":"2026-10-09T22:59:32.767965+00:00","authorized_by":"Olive alpha","policy_url":"https://example.com/policy"},"before":{"authorized_at":null,"authorized_by":null,"policy_url":null}}','b14fc89431f0cd208d7e36cf89a669f57e9104a3e6b9a3f03657feff9bd52bf6','0fdeee9f781dc74abf1ded8468d762baf29221bf1044c0fd883d511c32910e75','666580735c1f517dd8058c16c934004ba39dce7a7db9380f30c653a0846ef2a1');
INSERT INTO "audit_log" VALUES(7,7,'2026-10-09T22:59:32.771406+00:00','person',1,'Olive alpha','owner-alpha@example.com','members.updated',1,NULL,'{"after":[{"email":"reviewer-alpha@example.com","name":"Rita alpha","roles":["reviewer","tester"],"user_id":2},{"email":"viewer-alpha@example.com","name":"Vic alpha","roles":["viewer"],"user_id":3}],"before":[]}','a405934f465782b8d9fe45a268ce7ada71a721ce1e7cef57dc963addbefef35a','666580735c1f517dd8058c16c934004ba39dce7a7db9380f30c653a0846ef2a1','b34a1750f286b299a5f41e49fc007c5150e237cf9ef4071414b93ebd5711961a');
INSERT INTO "audit_log" VALUES(8,8,'2026-10-09T22:59:32.774063+00:00','person',1,'Olive alpha','owner-alpha@example.com','engagement.writes',1,NULL,'{"after":{"allow_writes":true},"before":{"allow_writes":false}}','b78d7a87b845c8375218212321ee31cb2a8912a7f86a853e23aabfb083685759','b34a1750f286b299a5f41e49fc007c5150e237cf9ef4071414b93ebd5711961a','2ae31030beabb3a60e3c45ac1a7fa5a880b1ddf9b72c8c055f84593d5b06239e');
INSERT INTO "audit_log" VALUES(9,9,'2026-10-09T22:59:32.774301+00:00','person',1,'Olive alpha','owner-alpha@example.com','engagement.retention',1,NULL,'{"after":{"retain_until":"2099-01-01"},"before":{"retain_until":null}}','03c647fb1b1c733369a19a325d901047dfda4fee09061a7bd163ce61798cb566','2ae31030beabb3a60e3c45ac1a7fa5a880b1ddf9b72c8c055f84593d5b06239e','863ce7b683c3897c5c9206c65a2bd9da4717e0f78554364436e1541e9daa3b42');
INSERT INTO "audit_log" VALUES(10,10,'2026-10-09T22:59:32.937336+00:00','person',1,'Olive alpha','owner-alpha@example.com','import.batch',1,NULL,'{"after":{"accepted":3,"batch_id":1,"creator":"Hand-made fixture 1.0","duplicates":1,"file_sha256":"1bc91e30a4eb79ecf7b4eb3d30a2c40073a5a082374e64d37c14370e8261e625","format":"har","out_of_scope":1,"out_of_scope_host_count":1,"rows":6,"unreadable":1}}','5735defa14b6dce4d96dc9a5dda7a9dddd162fea782fadae2367fca155f90e47','863ce7b683c3897c5c9206c65a2bd9da4717e0f78554364436e1541e9daa3b42','ac884fe5fdf1f874cf49b8ff8a8001442ad700e8c1f406dc9b46406e2ff78cf0');
INSERT INTO "audit_log" VALUES(11,11,'2026-10-09T22:59:32.947863+00:00','person',1,'Olive alpha','owner-alpha@example.com','import.dismissed',1,NULL,'{"after":{"entries":[2],"reason":"noise alpha"}}','d335e2ff4022211366aa0efe1c5f95f2b4e6c14e76f997adcacd4020dd94581c','ac884fe5fdf1f874cf49b8ff8a8001442ad700e8c1f406dc9b46406e2ff78cf0','53d6c82f0dd56dd752ba420dc9d598e046c406cde657a073257c941b9c47f0e3');
INSERT INTO "audit_log" VALUES(12,12,'2026-10-09T22:59:32.951140+00:00','person',1,'Olive alpha','owner-alpha@example.com','account.added',1,NULL,'{"after":{"fingerprint":"sha256:e75c5c295ab76724","header_names":["Cookie"],"hosts":["shop.alpha.example.com"],"kind":"cookie","label":"A","role":"customer alpha"}}','58de6ededaf91e6af63a3776d31b440e4e275e8c214445abf05e73dee40e9d3e','53d6c82f0dd56dd752ba420dc9d598e046c406cde657a073257c941b9c47f0e3','feb546f7bee90c09b8af5b3b8c8dd316df183268c3a3f5607eb4662c44e426a0');
CREATE TABLE checklist_items (
	id INTEGER NOT NULL, 
	lane_id INTEGER NOT NULL, 
	idx INTEGER NOT NULL, 
	item_key VARCHAR(64) NOT NULL, 
	text TEXT NOT NULL, 
	controls JSON NOT NULL, 
	state VARCHAR(4) NOT NULL, 
	na_reason TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(lane_id) REFERENCES lanes (id)
);
INSERT INTO "checklist_items" VALUES(1,1,1,'BUG-BOUNTY-RECON-01','Scope, required research header and rate limit confirmed against the live program policy','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','done',NULL);
INSERT INTO "checklist_items" VALUES(2,1,2,'BUG-BOUNTY-RECON-02','Information gathering: search engines, metafiles, entry points and framework fingerprint','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(3,1,3,'BUG-BOUNTY-RECON-03','Configuration: admin interfaces, HTTP methods, default and backup files, security headers','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25", "ISO-A.8.9"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(4,1,4,'BUG-BOUNTY-RECON-04','Transport security: TLS versions, certificates, HSTS, cookies sent over plain HTTP','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25", "ISO-A.8.24", "PCI-4.2.1"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(5,1,5,'BUG-BOUNTY-RECON-05','Cryptography in use where exposed: weak algorithms, padding, randomness','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25", "ISO-A.8.24"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(6,1,6,'BUG-BOUNTY-RECON-06','Source and secret leaks: repositories, backups, sourcemaps, keys in client code (never used)','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(7,1,7,'BUG-BOUNTY-RECON-07','Subdomains, including takeover candidates from dangling DNS records','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(8,1,8,'BUG-BOUNTY-RECON-08','Shadow and legacy APIs: old versions, undocumented paths, staging hosts','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(9,1,9,'BUG-BOUNTY-RECON-09','Network surface: open ports and services beyond the web','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(10,1,10,'BUG-BOUNTY-RECON-10','Cloud resources linked to the target: storage buckets, CDNs, cloud service settings','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(11,1,11,'BUG-BOUNTY-RECON-11','gRPC and other non-HTTP APIs (or N/A, with the signal that was checked)','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(12,1,12,'BUG-BOUNTY-RECON-12','Technology fingerprint recorded, including the identity provider ("none found" is a result)','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(13,1,13,'BUG-BOUNTY-RECON-13','Decision on each secret candidate: report, time-box or skip, with the reason','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(14,1,14,'BUG-BOUNTY-RECON-14','Handoff to the model lane: live endpoints and the authentication surface','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(15,1,15,'BUG-BOUNTY-RECON-15','Unexpected behaviour recorded as leads for other lanes (or N/A: none seen)','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(16,1,16,'BUG-BOUNTY-RECON-16','Every suspected finding re-verified independently before it is reported (or N/A: none)','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(17,1,17,'BUG-BOUNTY-RECON-17','Every negative result backed by a positive control showing the test could have found the issue','["ISO-A.5.9", "DORA-ART8", "PCI-6.3.1", "PCI-11.4.3", "ISO-A.8.8", "DORA-ART24", "DORA-ART25"]','na','lab alpha');
INSERT INTO "checklist_items" VALUES(18,2,1,'BUG-BOUNTY-MAPPER-01','JavaScript bundles and lazy-loaded chunks collected; API calls traced to their endpoints','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(19,2,2,'BUG-BOUNTY-MAPPER-02','GraphQL schema and operations inventoried (or N/A, with evidence that there is no GraphQL)','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(20,2,3,'BUG-BOUNTY-MAPPER-03','Calls the app makes before any identity-provider redirect recorded','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(21,2,4,'BUG-BOUNTY-MAPPER-04','Roles: every kind of user, and whether a test account exists for each','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(22,2,5,'BUG-BOUNTY-MAPPER-05','Objects: identifier format, ownership field, and the endpoints that read and write them','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(23,2,6,'BUG-BOUNTY-MAPPER-06','Flows: every step with its method, path and precondition','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(24,2,7,'BUG-BOUNTY-MAPPER-07','State machine: states, allowed transitions and the endpoint that triggers each one','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(25,2,8,'BUG-BOUNTY-MAPPER-08','Authentication required by every endpoint (anonymous, signed in, step-up) and the methods seen','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(26,2,9,'BUG-BOUNTY-MAPPER-09','Roles and objects that were not observed are marked unverified; nothing is assumed','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(27,2,10,'BUG-BOUNTY-MAPPER-10','Unexpected behaviour recorded as leads for other lanes (or N/A: none seen)','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(28,2,11,'BUG-BOUNTY-MAPPER-11','Every suspected finding re-verified independently before it is reported (or N/A: none)','[]','open',NULL);
INSERT INTO "checklist_items" VALUES(29,2,12,'BUG-BOUNTY-MAPPER-12','Every negative result backed by a positive control showing the test could have found the issue','[]','open',NULL);
CREATE TABLE endpoints (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	job_id INTEGER NOT NULL, 
	host VARCHAR(255) NOT NULL, 
	url TEXT NOT NULL, 
	url_sha256 VARCHAR(64) NOT NULL, 
	source VARCHAR(32) NOT NULL, 
	is_js BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(job_id) REFERENCES jobs (id), 
	UNIQUE (engagement_id, url_sha256)
);
INSERT INTO "endpoints" VALUES(1,1,2,'shop.alpha.example.com','https://shop.alpha.example.com/private-alpha/','ce42c05d43e11def81e05f3f5b5c5fb79d4deddf896f573387bfd9f026410c27','robots',0,'2026-10-09 22:59:32.806540');
CREATE TABLE "engagements" (
	id INTEGER NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	pack_id VARCHAR(64) NOT NULL, 
	engagement_type VARCHAR(20) NOT NULL, 
	policy_url VARCHAR(500), 
	created_at DATETIME NOT NULL, 
	scope_include JSON NOT NULL, 
	scope_exclude JSON NOT NULL, 
	authorized_by VARCHAR(200), 
	authorized_at DATETIME, 
	rate_limit_rps INTEGER NOT NULL, 
	research_header VARCHAR(300), 
	research_user_agent VARCHAR(300), 
	crawl_depth INTEGER DEFAULT '3' NOT NULL, 
	enabled_modules JSON NOT NULL, separation_of_duties BOOLEAN DEFAULT false NOT NULL, require_signatures BOOLEAN DEFAULT false NOT NULL, redact_evidence BOOLEAN DEFAULT true NOT NULL, retain_until DATE, content_deleted_at DATETIME, content_deleted_by VARCHAR(460), content_deleted_reason VARCHAR(16), allow_writes BOOLEAN DEFAULT false NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);
INSERT INTO "engagements" VALUES(1,'Engagement alpha','bug-bounty','bug_bounty','https://example.com/policy','2026-10-09 22:59:32.760560','["*.alpha.example.com"]','[]','Olive alpha','2026-10-09 22:59:32.767965',5,'X-Bug-Bounty: alpha',NULL,3,'[]',0,0,1,'2099-01-01',NULL,NULL,NULL,1);
CREATE TABLE "evidence" (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	seq INTEGER NOT NULL, 
	prev_hash VARCHAR(64) NOT NULL, 
	chain_hash VARCHAR(64) NOT NULL, 
	lane_id INTEGER NOT NULL, 
	item_id INTEGER, 
	kind VARCHAR(40) NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	uri VARCHAR(1000), 
	summary TEXT, 
	created_at DATETIME NOT NULL, 
	created_by INTEGER, 
	redaction JSON, 
	record_version INTEGER DEFAULT '1' NOT NULL, 
	summary_sha256 VARCHAR(64), 
	summary_enc TEXT, 
	source VARCHAR(40), 
	PRIMARY KEY (id), 
	CONSTRAINT fk_evidence_created_by_users FOREIGN KEY(created_by) REFERENCES users (id), 
	FOREIGN KEY(item_id) REFERENCES checklist_items (id), 
	FOREIGN KEY(lane_id) REFERENCES lanes (id), 
	UNIQUE (engagement_id, seq), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id)
);
INSERT INTO "evidence" VALUES(1,1,1,'0000000000000000000000000000000000000000000000000000000000000000','bd5fb7adb077359454666177d4c8bf2d5482e01d11e9b58f03bb4c9dce19d36f',1,NULL,'file','7dcb150b7a43ef52e2e2b85fabf3b5e5544f0854969af0c100201dcc93dddc67','job:1',NULL,'2026-10-09 22:59:32.798363',1,'null',2,'6e9e9bdfde1329b356c58961002db02a17f2c15ee80f2c66a16f1542084c86d7','ale1:pia8LMnFJPNM2/Dc1apY7imgloFexHrW/7xsEmqU/D29lA6QccmRyWqwt79shMMEpz1EDA==','recon');
INSERT INTO "evidence" VALUES(2,1,2,'bd5fb7adb077359454666177d4c8bf2d5482e01d11e9b58f03bb4c9dce19d36f','d74da03e843ac71da65064395cfad216babc134d33863aaa1a7cc539cdb72ad4',1,1,'note','2932dbaedbb93225efcd81c6d64b824d8b4c7ffd77d6feedd4fe7085cded13cb',NULL,NULL,'2026-10-09 22:59:32.814977',1,'{"redacted": 0, "kinds": [], "not_redacted": []}',2,'e6929390d1593e244c96c6a4f3e12aec86bb2e01cc1f9b43d64bcb120311d6d0','ale1:Qyn7R9AtHhKsfVsusQ+mQRvNnWmZ2ZikqSP6JdaW86tJBVm5t+k=','manual');
INSERT INTO "evidence" VALUES(3,1,3,'d74da03e843ac71da65064395cfad216babc134d33863aaa1a7cc539cdb72ad4','2bfe84b21844fbd73318350d8a56414bbccb3ab6243e66bb213506d0265cf232',2,18,'response','056ccc8ec2a15f176a9ae161f6f3cb4fae3330fd51cd161bba28f09458021ee7','https://shop.alpha.example.com/rest/user/login',NULL,'2026-10-09 22:59:32.944998',1,'{"redacted": 6, "kinds": ["Cookie", "password", "email address", "Set-Cookie", "token"], "not_redacted": []}',2,'f1a3bda98ae7eeacecbb9bb4c69bd4d7517e46cbc1a94f4782d82d6d4ed97395','ale1:jS1YQmIhUMAOGJF9jFpb/Lczv2Iz9AJLEHHolfg33ew/Sc9sLsxWTbeFvM6x1OJE3zHUo3EOiVGg1CYmoeOQ2b15eFS8NRGBy+f4+e00vUOc4M7Y1wzDzKldknYdD9hERdya9P6qP3/WVqNAZo+900BohAAgVNcNftzJykd5sfk/6nd2W/wMlRZCwE0OFxFxgBC1YeB2NAWT0AyiNbPmPi9+AlNp/H7yyZagCpgeJO+dmf5J059QVC7OHCkk3OC1of2q2s4E','import:har');
INSERT INTO "evidence" VALUES(4,1,4,'2bfe84b21844fbd73318350d8a56414bbccb3ab6243e66bb213506d0265cf232','700e29ffb6bfa0bb4660a0b0b79f7a7684705e80d13d407f9eeb1e508a3370fc',2,19,'response','1fdabc37846379faefd1a0dbb8020f6d8334efbd8cd780540b63f35b4270d64f','https://shop.alpha.example.com/',NULL,'2026-10-09 22:59:32.967458',1,'{"redacted": 0, "kinds": [], "not_redacted": []}',2,'5d92b66b50ffd1a639a2e71c4039d53db9b945c34e66a618962a597ade6bd2cf','ale1:lsfR8tOk1pcBlJEWBDmek14HofQviOgItBdKo8Lc+GYhk4vvF3o3ZcBQS1wS7DugGTSY1HfQUUYGbphFDR+EOH7RbZMu0pdZhJYniU4TQY15ufxHK4U82gr1kVcSvR0=','agent');
CREATE TABLE gateway_requests (
	id INTEGER NOT NULL, 
	at DATETIME NOT NULL, 
	engagement_id INTEGER, 
	job_id INTEGER, 
	tool VARCHAR(32) NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	method VARCHAR(16) NOT NULL, 
	url TEXT NOT NULL, 
	host VARCHAR(255) NOT NULL, 
	port INTEGER, 
	status INTEGER, 
	verdict VARCHAR(8) NOT NULL, 
	reason VARCHAR(300) NOT NULL, 
	bytes_sent INTEGER NOT NULL, 
	bytes_received INTEGER NOT NULL, 
	duration_ms INTEGER, account VARCHAR(16), approval_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(job_id) REFERENCES jobs (id)
);
INSERT INTO "gateway_requests" VALUES(1,'2026-10-09 22:59:32.971442',1,3,'agent','target','GET','https://shop.alpha.example.com/','shop.alpha.example.com',NULL,200,'allowed','',0,0,NULL,NULL,NULL);
INSERT INTO "gateway_requests" VALUES(2,'2026-10-09 22:59:32.971442',NULL,NULL,'dns','dns','DNS','refused.alpha.example.org','refused.alpha.example.org',NULL,NULL,'refused','not in scope alpha',0,0,NULL,NULL,NULL);
CREATE TABLE import_batches (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	tool VARCHAR(16) NOT NULL, 
	creator VARCHAR(200), 
	filename VARCHAR(200), 
	file_sha256 VARCHAR(64) NOT NULL, 
	file_bytes INTEGER NOT NULL, 
	rows INTEGER NOT NULL, 
	accepted INTEGER NOT NULL, 
	out_of_scope INTEGER NOT NULL, 
	duplicates INTEGER NOT NULL, 
	unreadable INTEGER NOT NULL, 
	refused JSON NOT NULL, 
	created_by INTEGER, 
	created_by_name VARCHAR(300) NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);
INSERT INTO "import_batches" VALUES(1,1,'har','Hand-made fixture 1.0','alpha.har','1bc91e30a4eb79ecf7b4eb3d30a2c40073a5a082374e64d37c14370e8261e625',5301,6,3,1,1,1,'[{"row": 5, "host": null, "reason": "unreadable", "detail": "no readable URL"}, {"row": 3, "host": "tracker.example.net", "reason": "out_of_scope", "detail": null}, {"row": 6, "host": "shop.alpha.example.com", "reason": "duplicate", "detail": null}]',1,'Olive alpha (owner-alpha@example.com)','2026-10-09 22:59:32.934694');
CREATE TABLE inbox_entries (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	batch_id INTEGER NOT NULL, 
	"row" INTEGER NOT NULL, 
	tool VARCHAR(16) NOT NULL, 
	tool_id VARCHAR(100), 
	tool_time VARCHAR(64), 
	host VARCHAR(255) NOT NULL, 
	method VARCHAR(20) NOT NULL, 
	url TEXT NOT NULL, 
	status INTEGER, 
	label VARCHAR(300), 
	request_sha256 VARCHAR(64), 
	response_sha256 VARCHAR(64), 
	record_sha256 VARCHAR(64) NOT NULL, 
	content_sha256 VARCHAR(64) NOT NULL, 
	request_bytes INTEGER NOT NULL, 
	response_bytes INTEGER NOT NULL, 
	facts JSON NOT NULL, 
	redaction JSON, 
	state VARCHAR(16) DEFAULT 'new' NOT NULL, 
	mappings JSON NOT NULL, 
	dismissed_by INTEGER, 
	dismissed_by_name VARCHAR(300), 
	dismissed_at DATETIME, 
	dismiss_reason VARCHAR(500), 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (engagement_id, content_sha256), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(batch_id) REFERENCES import_batches (id), 
	FOREIGN KEY(dismissed_by) REFERENCES users (id)
);
INSERT INTO "inbox_entries" VALUES(1,1,1,1,'har',NULL,'2026-10-09T10:00:00.000Z','shop.alpha.example.com','POST','https://shop.alpha.example.com/rest/user/login',200,'sign-in','ce51e55767af9fe3971d4e5ccfcb27f2c34866689b00785ecd1fec9e39a1ecd7','0fe2d1fc2d8226966bdc7c4bd9d41341fe7b578f76edcb714185ecbbfa30b635','056ccc8ec2a15f176a9ae161f6f3cb4fae3330fd51cd161bba28f09458021ee7','09ffbf88ea8026bb71f2448545eafac758977758638d4dcc2bef1a5cd7262fa1',271,182,'{"content_type": "application/json", "sets_cookie": true, "cors": false, "upgrade": "", "notes": ["raw bytes rebuilt from the export''s fields"]}','{"redacted": 6, "kinds": ["Cookie", "password", "email address", "Set-Cookie", "token"], "not_redacted": [], "counts": {"Cookie": 2, "password": 1, "email address": 1, "Set-Cookie": 1, "token": 1}}','mapped','[{"evidence_id": 3, "lane_id": 2, "item_idx": 1, "item_key": "BUG-BOUNTY-MAPPER-01", "by": 1, "by_name": "Olive alpha (owner-alpha@example.com)", "at": "2026-10-09T22:59:32.945094+00:00"}]',NULL,NULL,NULL,NULL,'2026-10-09 22:59:32.937035');
INSERT INTO "inbox_entries" VALUES(2,1,1,2,'har',NULL,'2026-10-09T10:00:01.000Z','shop.alpha.example.com','GET','https://shop.alpha.example.com/api/accounts/7?access_token=[redacted:sha256:b25d71ae7a97]&fields=name',403,NULL,'d4fc5e60454a55e46bf59582fcb31b43fcc685ecfe8f488fbe93332aa691f314','67ea03a67959591436af5a250f6f51071911f67cfc21691460dd3c772a389ec9','b11ff6f2bf746a201e397b9a974b5847356bc59841d5a0626374bd1430714b54','ea99780ab3953600e77927bbed45d138b86f9c4109f854d93d1d365468b096cc',219,77,'{"content_type": "application/json", "sets_cookie": false, "cors": false, "upgrade": "", "notes": ["raw bytes rebuilt from the export''s fields"]}','{"redacted": 4, "kinds": ["access_token", "Authorization", "X-Api-Key"], "not_redacted": [], "counts": {"access_token": 2, "Authorization": 1, "X-Api-Key": 1}}','dismissed','[]',1,'Olive alpha (owner-alpha@example.com)','2026-10-09 22:59:32.947773','noise alpha','2026-10-09 22:59:32.937036');
INSERT INTO "inbox_entries" VALUES(3,1,1,4,'har',NULL,'2026-10-09T10:00:03.000Z','shop.alpha.example.com','GET','https://shop.alpha.example.com/robots.txt',200,NULL,'d23d4a704cea6f1c8c747a3453abe3eb1df4663e94bc00dc41eb84e0e3be3312','e1ca07ca22813faaa046d5b9d9c57f1d29d0bf538f096b2b5c9ca18ca41a2e71','a9b35b9e247e363f8ce3965295a45cb2d9d712aa9a341c9d6251c26b406a1fad','c0585050ff5ffa7e9af08d2cc2ff69ab8d6c8cdfd783458cadd357b1f35635dc',28,74,'{"content_type": "text/plain", "sets_cookie": false, "cors": false, "upgrade": "", "notes": ["raw bytes rebuilt from the export''s fields"]}','{"redacted": 0, "kinds": [], "not_redacted": [], "counts": {}}','new','[]',NULL,NULL,NULL,NULL,'2026-10-09 22:59:32.937037');
CREATE TABLE "jobs" (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	kind VARCHAR(40) NOT NULL, 
	targets JSON NOT NULL, 
	status VARCHAR(9) NOT NULL, 
	log TEXT NOT NULL, 
	result_count INTEGER NOT NULL, 
	output_sha256 VARCHAR(64), 
	created_at DATETIME NOT NULL, 
	started_at DATETIME, 
	finished_at DATETIME, 
	targets_done INTEGER DEFAULT '0' NOT NULL, 
	remaining_targets JSON, 
	"deferred" BOOLEAN DEFAULT (false) NOT NULL, 
	lane_id INTEGER, 
	result JSON, 
	created_by INTEGER, gateway_secret_sha256 VARCHAR(64), worker_token_sha256 VARCHAR(64), heartbeat_at DATETIME, driver VARCHAR(200), 
	PRIMARY KEY (id), 
	CONSTRAINT fk_jobs_lane_id_lanes FOREIGN KEY(lane_id) REFERENCES lanes (id), 
	CONSTRAINT fk_jobs_created_by_users FOREIGN KEY(created_by) REFERENCES users (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id)
);
INSERT INTO "jobs" VALUES(1,1,'resolve','["shop.alpha.example.com"]','done','',1,'7dcb150b7a43ef52e2e2b85fabf3b5e5544f0854969af0c100201dcc93dddc67','2026-10-09 22:59:32.784531','2026-10-09 22:59:32.786317','2026-10-09 22:59:32.798862',1,'null',0,NULL,NULL,1,NULL,NULL,'2026-10-09 22:59:32.794335',NULL);
INSERT INTO "jobs" VALUES(2,1,'wellknown','["https://shop.alpha.example.com/"]','done','',2,NULL,'2026-10-09 22:59:32.801581','2026-10-09 22:59:32.802857','2026-10-09 22:59:32.810541',1,'null',0,NULL,NULL,1,NULL,NULL,'2026-10-09 22:59:32.809787',NULL);
INSERT INTO "jobs" VALUES(3,1,'agent','["shop.alpha.example.com"]','running','',0,NULL,'2026-10-09 22:59:32.954043','2026-10-09 22:59:32.955849',NULL,0,NULL,0,2,'{"limits": {"max_turns": 15, "max_requests": 30, "max_cost_usd": 0.5}}',1,'fc1f86d66ccae88aad2019b81b8f6bfc169ed05e590c582cc7a20f39e012942d','5cd6a1c625019f15aad943fc07a729d08f5bdfac4f0d6b44f310f8d85c45326f','2026-10-09 22:59:32.968652','driver alpha');
CREATE TABLE key_log (
	id INTEGER NOT NULL, 
	seq INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	user_name VARCHAR(200) NOT NULL, 
	key_fingerprint VARCHAR(64) NOT NULL, 
	algorithm VARCHAR(20) NOT NULL, 
	event VARCHAR(16) NOT NULL, 
	at VARCHAR(40) NOT NULL, 
	via VARCHAR(24) NOT NULL, 
	record_sha256 VARCHAR(64) NOT NULL, 
	prev_hash VARCHAR(64) NOT NULL, 
	entry_hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (seq), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);
INSERT INTO "key_log" VALUES(1,1,2,'Rita alpha','2653e843a2ed5336edf6004fa8c4044e48e7351c2d5ba21cef53ae483bc903cd','Ed25519','registered','2026-10-09T22:59:32.894181+00:00','assigned_password','62a28693a66abd956eb36e637f4ae5403ef856bf057832e70a986ae390d73f29','0000000000000000000000000000000000000000000000000000000000000000','add3cd097e4706fcda44d601f853c2f87811d143c828f5ea4ce8351c7356bc16');
CREATE TABLE lanes (
	id INTEGER NOT NULL, 
	asset_id INTEGER NOT NULL, 
	role VARCHAR(32) NOT NULL, 
	opened_at DATETIME NOT NULL, executor VARCHAR(16) DEFAULT 'manual' NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(asset_id) REFERENCES assets (id), 
	UNIQUE (asset_id, role)
);
INSERT INTO "lanes" VALUES(1,1,'recon','2026-10-09 22:59:32.779924','manual');
INSERT INTO "lanes" VALUES(2,1,'mapper','2026-10-09 22:59:32.930072','agent');
CREATE TABLE leads (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	job_id INTEGER NOT NULL, 
	host VARCHAR(255) NOT NULL, 
	source_url TEXT NOT NULL, 
	kind VARCHAR(32) NOT NULL, 
	title VARCHAR(300) NOT NULL, 
	bucket VARCHAR(16) NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	detail JSON NOT NULL, 
	fingerprint VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(job_id) REFERENCES jobs (id), 
	UNIQUE (engagement_id, fingerprint)
);
INSERT INTO "leads" VALUES(1,1,2,'shop.alpha.example.com','https://shop.alpha.example.com/robots.txt','robots','robots names /private-alpha/','','','{}','d522137dd0cb7ca679d612616adcbbeedf8686300a7b3b1eb291cf0562aee2aa','2026-10-09 22:59:32.806790');
CREATE TABLE memberships (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	roles JSON NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (engagement_id, user_id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);
INSERT INTO "memberships" VALUES(1,1,2,'["reviewer", "tester"]');
INSERT INTO "memberships" VALUES(2,1,3,'["viewer"]');
CREATE TABLE observations (
	id INTEGER NOT NULL, 
	job_id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	host VARCHAR(255) NOT NULL, 
	data JSON NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(job_id) REFERENCES jobs (id)
);
INSERT INTO "observations" VALUES(1,1,1,'shop.alpha.example.com','{"a": ["192.0.2.10"]}','2026-10-09 22:59:32.791134');
CREATE TABLE "receipts" (
	id INTEGER NOT NULL, 
	lane_id INTEGER NOT NULL, 
	manifest_sha256 VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	closed_by VARCHAR(200), 
	closed_by_user INTEGER, payload TEXT, signature VARCHAR(200), algorithm VARCHAR(20), public_key TEXT, key_fingerprint VARCHAR(64), timestamp_token TEXT, timestamp_time DATETIME, timestamp_tsa VARCHAR(500), timestamp_error VARCHAR(500), closed_by_email VARCHAR(254), 
	PRIMARY KEY (id), 
	CONSTRAINT fk_receipts_closed_by_user_users FOREIGN KEY(closed_by_user) REFERENCES users (id), 
	FOREIGN KEY(lane_id) REFERENCES lanes (id)
);
INSERT INTO "receipts" VALUES(1,1,'90728ca69fe07c2b1c8242c24621b1fb235685e7b732f6fdaba9009ee7d92d0d','2026-10-09 22:59:32.900829','Rita alpha',2,'{"chain":{"head":"d74da03e843ac71da65064395cfad216babc134d33863aaa1a7cc539cdb72ad4","seq":2},"engagement":{"id":1,"name":"Engagement alpha"},"format":"attackledger-receipt-v3","issued_at":"2026-10-09T22:59:32+00:00","key_fingerprint":"2653e843a2ed5336edf6004fa8c4044e48e7351c2d5ba21cef53ae483bc903cd","lane":{"host":"shop.alpha.example.com","id":1,"role":"recon"},"manifest_sha256":"90728ca69fe07c2b1c8242c24621b1fb235685e7b732f6fdaba9009ee7d92d0d","signer":{"email":"reviewer-alpha@example.com","id":2,"name":"Rita alpha"}}','edVGSorOXnqGt0htf+fRGZRbCBFNslXAmN4m21vORGMR3JTcyYkzrU1wOlqblp64U7IQYZDRXYO4gEeNnoE8Dw==','Ed25519','MCowBQYDK2VwAyEA/tg/XfhmiwBAXAN5oRtLH7l8rbyfyPlXKi/7ojKn+Xo=','2653e843a2ed5336edf6004fa8c4044e48e7351c2d5ba21cef53ae483bc903cd',NULL,NULL,NULL,NULL,'reviewer-alpha@example.com');
CREATE TABLE signing_keys (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	algorithm VARCHAR(20) NOT NULL, 
	public_key TEXT NOT NULL, 
	fingerprint VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	revoked_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id), 
	UNIQUE (fingerprint)
);
INSERT INTO "signing_keys" VALUES(1,2,'Ed25519','MCowBQYDK2VwAyEA/tg/XfhmiwBAXAN5oRtLH7l8rbyfyPlXKi/7ojKn+Xo=','2653e843a2ed5336edf6004fa8c4044e48e7351c2d5ba21cef53ae483bc903cd','2026-10-09 22:59:32.893661',NULL);
CREATE TABLE test_accounts (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	label VARCHAR(16) NOT NULL, 
	role VARCHAR(100) NOT NULL, 
	hosts JSON NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	header_names JSON NOT NULL, 
	material_enc TEXT NOT NULL, 
	fingerprint VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	created_by INTEGER, 
	replaced_at DATETIME, 
	last_used_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (engagement_id, label), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);
INSERT INTO "test_accounts" VALUES(1,1,'A','customer alpha','["shop.alpha.example.com"]','cookie','["Cookie"]','ale1:vwc78mWsyEMrtf1k/Z8A8uz1fsER3suGNZ5/kNb3xKidBIIK7nIfsgle390rPXyb+nYP/k+uTOq+me9OO7XDcA==','e75c5c295ab7672483a130323c1e5e056cca8afd2739117de5d024f66630306c','2026-10-09 22:59:32.950937',1,NULL,NULL);
CREATE TABLE user_sessions (
	id INTEGER NOT NULL, 
	token_sha256 VARCHAR(64) NOT NULL, 
	user_id INTEGER NOT NULL, 
	created_at DATETIME NOT NULL, 
	expires_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (token_sha256), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);
INSERT INTO "user_sessions" VALUES(1,'ddee6e7d562c9d81ff2cf1b5ef04f73f21192206fc105f323a0f5caeac4231d1',1,'2026-10-09 22:59:32.705186','2026-10-10 10:59:32.705186');
INSERT INTO "user_sessions" VALUES(2,'cb2e4ef4f4c59cb6a68bd9541a2dab09c5795cf110014cedcb924ff2853e5655',2,'2026-10-09 22:59:32.889025','2026-10-10 10:59:32.889025');
INSERT INTO "user_sessions" VALUES(3,'d38f5f3615ae1c412e528adcbf772cb7bfad0fdd2196d779cca691f17bb27b32',1,'2026-10-09 22:59:32.926719','2026-10-10 10:59:32.926719');
CREATE TABLE users (
	id INTEGER NOT NULL, 
	email VARCHAR(254) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	password_hash VARCHAR(300) NOT NULL, 
	is_owner BOOLEAN DEFAULT false NOT NULL, 
	disabled BOOLEAN DEFAULT false NOT NULL, 
	created_at DATETIME NOT NULL, password_chosen BOOLEAN DEFAULT false NOT NULL, last_sign_in_at DATETIME, previous_sign_in_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (email)
);
INSERT INTO "users" VALUES(1,'owner-alpha@example.com','Olive alpha','scrypt$16384$8$1$77d1a269455dda3b4880076a37278208$cbb8636ca6518ed7fb2ec446b96e294457339cada9e4091541c70663b9664cd7',1,0,'2026-10-09 22:59:32.679023',0,'2026-10-09 22:59:32.926689','2026-10-09 22:59:32.705161');
INSERT INTO "users" VALUES(2,'reviewer-alpha@example.com','Rita alpha','scrypt$16384$8$1$3e4173f08e495cfa9872ac8e2438bf01$7180937176a4d4491f5df69bc03f0b7bf704d061d94b61d42d2c8e13c783c6a4',0,0,'2026-10-09 22:59:32.732366',0,'2026-10-09 22:59:32.888994',NULL);
INSERT INTO "users" VALUES(3,'viewer-alpha@example.com','Vic alpha','scrypt$16384$8$1$60cd8992ade9590c37ff76fa0f7c3595$8c099d6ae2e87b62d2efc7d68ae2e67a62305f1d3acbaf00f4664de24cd4beb4',0,0,'2026-10-09 22:59:32.757230',0,NULL,NULL);
CREATE TABLE write_proposals (
	id INTEGER NOT NULL, 
	engagement_id INTEGER NOT NULL, 
	lane_id INTEGER NOT NULL, 
	job_id INTEGER, 
	item_idx INTEGER, 
	method VARCHAR(8) NOT NULL, 
	url TEXT NOT NULL, 
	host VARCHAR(255) NOT NULL, 
	account VARCHAR(16), 
	reason TEXT NOT NULL, 
	request_enc TEXT, 
	request_sha256 VARCHAR(64) NOT NULL, 
	body_sha256 VARCHAR(64) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	decided_by INTEGER, 
	decided_by_name VARCHAR(460), 
	decided_at DATETIME, 
	decision_note TEXT, 
	approved_sha256 VARCHAR(64), 
	delete_confirmed_at DATETIME, 
	expires_at DATETIME, 
	sent_at DATETIME, 
	response_status INTEGER, 
	exchange_id VARCHAR(16), 
	evidence_id INTEGER, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id), 
	FOREIGN KEY(lane_id) REFERENCES lanes (id), 
	FOREIGN KEY(job_id) REFERENCES jobs (id), 
	FOREIGN KEY(decided_by) REFERENCES users (id), 
	FOREIGN KEY(evidence_id) REFERENCES evidence (id)
);
INSERT INTO "write_proposals" VALUES(1,1,2,3,1,'POST','https://shop.alpha.example.com/api/basket','shop.alpha.example.com',NULL,'try alpha','ale1:FkUVc0fwCOy8z4ybPFMl227Lcvi6edAi9p8rdxXUzlpR1QFRQnO3/Pt/tQEcHIPMpbaBMaxymCMjwimpEaOzIgOZ79KUvMEs+VoGBYYffjdg4DMnkXfauha4PZuMtCe2MFsZhfYR3PdWtOZ3S2d3K1D4jP0IKYrIJOqMgk3krsBztuUVhDcT+w35E1Mx','9e723b754769b24f1e070b7bf9f1131b521b2f960c22bda9906f3b4f572a8ce9','44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a','pending',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'2026-10-09 22:59:32.970736');
CREATE INDEX ix_key_log_user_id ON key_log (user_id);
CREATE INDEX ix_key_log_key_fingerprint ON key_log (key_fingerprint);
CREATE INDEX ix_audit_log_engagement_id ON audit_log (engagement_id);
CREATE INDEX ix_audit_log_subject_id ON audit_log (subject_id);
CREATE INDEX ix_import_batches_engagement_id ON import_batches (engagement_id);
CREATE INDEX ix_inbox_entries_engagement_id ON inbox_entries (engagement_id);
CREATE INDEX ix_inbox_entries_batch_id ON inbox_entries (batch_id);
CREATE INDEX ix_gateway_requests_engagement_id ON gateway_requests (engagement_id);
CREATE INDEX ix_gateway_requests_job_id ON gateway_requests (job_id);
CREATE INDEX ix_agent_exchanges_job_id ON agent_exchanges (job_id);
CREATE INDEX ix_test_accounts_engagement_id ON test_accounts (engagement_id);
CREATE INDEX ix_write_proposals_engagement_id ON write_proposals (engagement_id);
CREATE INDEX ix_write_proposals_job_id ON write_proposals (job_id);
COMMIT;
