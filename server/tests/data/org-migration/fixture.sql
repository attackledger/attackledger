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
INSERT INTO "agent_exchanges" VALUES(1,3,'x1','9f90d4f480319488a5c1419a67474ba8e4239e587308dd0b4500072319e5a519','GET','https://shop.alpha.example.com/',200,'{"kinds": {}, "not_redacted": []}','2026-10-09 23:39:45.572072',NULL,NULL);
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
INSERT INTO "audit_log" VALUES(1,1,'2026-10-09T23:39:45.283992+00:00','open',NULL,'open mode',NULL,'person.created',NULL,1,'{"after":{"disabled":false,"email":"owner-alpha@example.com","is_owner":true,"name":"Olive alpha"},"password":"assigned","person":{"email":"owner-alpha@example.com","id":1,"name":"Olive alpha"}}','e7fa41190050a39dac0a5dbd67987e522501f7790900540dcd1b3cc7f66bc9ca','0000000000000000000000000000000000000000000000000000000000000000','afd51deec48bedd42db16f90ba347bb38c96b87dc68d19f6f2aa82b0656dd488');
INSERT INTO "audit_log" VALUES(2,2,'2026-10-09T23:39:45.336933+00:00','person',1,'Olive alpha','owner-alpha@example.com','person.created',NULL,2,'{"after":{"disabled":false,"email":"reviewer-alpha@example.com","is_owner":false,"name":"Rita alpha"},"password":"assigned","person":{"email":"reviewer-alpha@example.com","id":2,"name":"Rita alpha"}}','689133da4ef17612955232f82fd6468e4ce826a4b9fc01ba40b627adbb99008c','afd51deec48bedd42db16f90ba347bb38c96b87dc68d19f6f2aa82b0656dd488','f9a9c175b58d3e27774c0b29d18d35291de85f3585731f1770c0b53fe007ca57');
INSERT INTO "audit_log" VALUES(3,3,'2026-10-09T23:39:45.361249+00:00','person',1,'Olive alpha','owner-alpha@example.com','person.created',NULL,3,'{"after":{"disabled":false,"email":"viewer-alpha@example.com","is_owner":false,"name":"Vic alpha"},"password":"assigned","person":{"email":"viewer-alpha@example.com","id":3,"name":"Vic alpha"}}','a98b06ac949c166560d706f8d576a8228ba6c8c4f12558b00c49d8e1fb6bf3f0','f9a9c175b58d3e27774c0b29d18d35291de85f3585731f1770c0b53fe007ca57','945be23fa6a8ba49388066de15c3c5289e20a583cba2da373a35ec5713bccfd6');
INSERT INTO "audit_log" VALUES(4,4,'2026-10-09T23:39:45.364780+00:00','person',1,'Olive alpha','owner-alpha@example.com','engagement.created',1,NULL,'{"after":{"engagement_type":"bug_bounty","name":"Engagement alpha","pack_id":"bug-bounty","policy_url":null}}','b0e9ed19422b04507acf8d9f4264b4e6f6754d16d65246ab786f533bd999599e','945be23fa6a8ba49388066de15c3c5289e20a583cba2da373a35ec5713bccfd6','b7097ebb9754a4e677ad75bb73dd8c5a5f45fa0256e7e1a604ea6b50001802cf');
INSERT INTO "audit_log" VALUES(5,5,'2026-10-09T23:39:45.369665+00:00','person',1,'Olive alpha','owner-alpha@example.com','scope.updated',1,NULL,'{"after":{"crawl_depth":3,"enabled_modules":[],"exclude":[],"include":["*.alpha.example.com"],"rate_limit_rps":5,"research_header":"X-Bug-Bounty: alpha","research_user_agent":null},"before":{"crawl_depth":3,"enabled_modules":[],"exclude":[],"include":[],"rate_limit_rps":5,"research_header":null,"research_user_agent":null}}','00a174f37671014e82b919a9be165b293482ddcac391475cf84d3ba44aad7a15','b7097ebb9754a4e677ad75bb73dd8c5a5f45fa0256e7e1a604ea6b50001802cf','60457c359d2d9acd26b99f8e6aa133f1ed83e3453a37154b88188c55d782f20b');
INSERT INTO "audit_log" VALUES(6,6,'2026-10-09T23:39:45.372269+00:00','person',1,'Olive alpha','owner-alpha@example.com','engagement.authorized',1,NULL,'{"after":{"authorized_at":"2026-10-09T23:39:45.372164+00:00","authorized_by":"Olive alpha","policy_url":"https://example.com/policy"},"before":{"authorized_at":null,"authorized_by":null,"policy_url":null}}','9a80e13b7e10183bf6f119ceaa4faad266e66e82e865981fdc415ecb73ff272d','60457c359d2d9acd26b99f8e6aa133f1ed83e3453a37154b88188c55d782f20b','b9df8ede0b1a11ff512b0e75f547fa9ec8e0b5e8b2b326d9859687218015ea79');
INSERT INTO "audit_log" VALUES(7,7,'2026-10-09T23:39:45.375766+00:00','person',1,'Olive alpha','owner-alpha@example.com','members.updated',1,NULL,'{"after":[{"email":"reviewer-alpha@example.com","name":"Rita alpha","roles":["reviewer","tester"],"user_id":2},{"email":"viewer-alpha@example.com","name":"Vic alpha","roles":["viewer"],"user_id":3}],"before":[]}','2d6feddcdd4dae2e6ca7052d79197feaa82bb4d45849f5a484526bc7fe9c7e94','b9df8ede0b1a11ff512b0e75f547fa9ec8e0b5e8b2b326d9859687218015ea79','9cff2b7dd3cc7b102e24a8f1e6a1c2d8eac6555aba257280359ac7095c7f00b7');
INSERT INTO "audit_log" VALUES(8,8,'2026-10-09T23:39:45.378301+00:00','person',1,'Olive alpha','owner-alpha@example.com','engagement.writes',1,NULL,'{"after":{"allow_writes":true},"before":{"allow_writes":false}}','cf877a280763e8a4b82fa8628a8b44657917a133a297195a1af5173fd8b5e995','9cff2b7dd3cc7b102e24a8f1e6a1c2d8eac6555aba257280359ac7095c7f00b7','21ee654d95b7bd25e62cf101d8305e3e91b9be3003c9b3a419a3cfe363472170');
INSERT INTO "audit_log" VALUES(9,9,'2026-10-09T23:39:45.378520+00:00','person',1,'Olive alpha','owner-alpha@example.com','engagement.retention',1,NULL,'{"after":{"retain_until":"2099-01-01"},"before":{"retain_until":null}}','58f6d9d6358a91f25df632ca700422a7c8e39d5e580a7306d3709e9b875de89d','21ee654d95b7bd25e62cf101d8305e3e91b9be3003c9b3a419a3cfe363472170','b92a2536718502d1afb3bf367be759db100b05b07e0dbd22eda801be4dc1ca93');
INSERT INTO "audit_log" VALUES(10,10,'2026-10-09T23:39:45.546537+00:00','person',1,'Olive alpha','owner-alpha@example.com','import.batch',1,NULL,'{"after":{"accepted":3,"batch_id":1,"creator":"Hand-made fixture 1.0","duplicates":1,"file_sha256":"1bc91e30a4eb79ecf7b4eb3d30a2c40073a5a082374e64d37c14370e8261e625","format":"har","out_of_scope":1,"out_of_scope_host_count":1,"rows":6,"unreadable":1}}','4704327b774102ff103a95c9bc65a28b0093f1ff9c79758272e7ab8bf18272dd','b92a2536718502d1afb3bf367be759db100b05b07e0dbd22eda801be4dc1ca93','d9008ecc345e8d55b151c0bd47901d31ae0e339e60e069efe940692153c8029e');
INSERT INTO "audit_log" VALUES(11,11,'2026-10-09T23:39:45.556941+00:00','person',1,'Olive alpha','owner-alpha@example.com','import.dismissed',1,NULL,'{"after":{"entries":[2],"reason":"noise alpha"}}','4fc868d90a568c1f443952cb94e6d87323119d69a6f784c76be59dca8797cbdf','d9008ecc345e8d55b151c0bd47901d31ae0e339e60e069efe940692153c8029e','c4578c8d4da4a40544c14b19c9de6c325bcfe7a62da270422855b968a09aa07b');
INSERT INTO "audit_log" VALUES(12,12,'2026-10-09T23:39:45.560106+00:00','person',1,'Olive alpha','owner-alpha@example.com','account.added',1,NULL,'{"after":{"fingerprint":"sha256:e75c5c295ab76724","header_names":["Cookie"],"hosts":["shop.alpha.example.com"],"kind":"cookie","label":"A","role":"customer alpha"}}','0a8ae0069195208031bc30455b7950055b412edc9532ca358f1785d6a862d0c7','c4578c8d4da4a40544c14b19c9de6c325bcfe7a62da270422855b968a09aa07b','e2d62ec1371de9bb3faf301b9522f360d64e1d8b6bb24c0b1178eccf144122b1');
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
INSERT INTO "endpoints" VALUES(1,1,2,'shop.alpha.example.com','https://shop.alpha.example.com/private-alpha/','ce42c05d43e11def81e05f3f5b5c5fb79d4deddf896f573387bfd9f026410c27','robots',0,'2026-10-09 23:39:45.413821');
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
INSERT INTO "engagements" VALUES(1,'Engagement alpha','bug-bounty','bug_bounty','https://example.com/policy','2026-10-09 23:39:45.364495','["*.alpha.example.com"]','[]','Olive alpha','2026-10-09 23:39:45.372164',5,'X-Bug-Bounty: alpha',NULL,3,'[]',0,0,1,'2099-01-01',NULL,NULL,NULL,1);
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
	UNIQUE (engagement_id, seq), 
	FOREIGN KEY(lane_id) REFERENCES lanes (id), 
	FOREIGN KEY(item_id) REFERENCES checklist_items (id), 
	FOREIGN KEY(engagement_id) REFERENCES engagements (id)
);
INSERT INTO "evidence" VALUES(1,1,1,'0000000000000000000000000000000000000000000000000000000000000000','bd5fb7adb077359454666177d4c8bf2d5482e01d11e9b58f03bb4c9dce19d36f',1,NULL,'file','7dcb150b7a43ef52e2e2b85fabf3b5e5544f0854969af0c100201dcc93dddc67','job:1',NULL,'2026-10-09 23:39:45.404955',1,'null',2,'6e9e9bdfde1329b356c58961002db02a17f2c15ee80f2c66a16f1542084c86d7','ale1:n/IqhSOc/qQa2JeVJUbdfnR7/fVLScWeVmtiGStrW16CO91MCwR37ShZ8MKo+AzuwJldug==','recon');
INSERT INTO "evidence" VALUES(2,1,2,'bd5fb7adb077359454666177d4c8bf2d5482e01d11e9b58f03bb4c9dce19d36f','d74da03e843ac71da65064395cfad216babc134d33863aaa1a7cc539cdb72ad4',1,1,'note','2932dbaedbb93225efcd81c6d64b824d8b4c7ffd77d6feedd4fe7085cded13cb',NULL,NULL,'2026-10-09 23:39:45.423216',1,'{"redacted": 0, "kinds": [], "not_redacted": []}',2,'e6929390d1593e244c96c6a4f3e12aec86bb2e01cc1f9b43d64bcb120311d6d0','ale1:NCU8JN3yglbTvV6C7Q7AMPefhjGV4kdLqiCBb+HE/pJ0Bwdw5Ts=','manual');
INSERT INTO "evidence" VALUES(3,1,3,'d74da03e843ac71da65064395cfad216babc134d33863aaa1a7cc539cdb72ad4','2bfe84b21844fbd73318350d8a56414bbccb3ab6243e66bb213506d0265cf232',2,18,'response','056ccc8ec2a15f176a9ae161f6f3cb4fae3330fd51cd161bba28f09458021ee7','https://shop.alpha.example.com/rest/user/login',NULL,'2026-10-09 23:39:45.553949',1,'{"redacted": 6, "kinds": ["Cookie", "password", "email address", "Set-Cookie", "token"], "not_redacted": []}',2,'f1a3bda98ae7eeacecbb9bb4c69bd4d7517e46cbc1a94f4782d82d6d4ed97395','ale1:g2Mj+3VBGAUvtZbxY5+RQb4KZTHvYj47jXbRFqV5wPQDEY5gefaa+IX6xNdG8Es7XZEVtvo0hXkndKXjJWL9oUUrWpnzMnxP95h2Lfh3w5culxoCczligC3ZkKkJkyxvMQMvHgrRq+J/CO6dml5I8RYXN/qQpuahT01G/vpO6xUVXlxO9x75ZDYFhEom0VSLjD4ANLrpAtVVxk6rGJGpYzu3Qx/LfPzzdp+KUeL8CeK4r8g2KMdeG+bh53ne9yeJoa/ro3mx','import:har');
INSERT INTO "evidence" VALUES(4,1,4,'2bfe84b21844fbd73318350d8a56414bbccb3ab6243e66bb213506d0265cf232','affe9ce7bb4de6a8b7d05415a1ea42cf4a76aed2b0eab651e65ed8e21acef0ae',2,19,'response','9f90d4f480319488a5c1419a67474ba8e4239e587308dd0b4500072319e5a519','https://shop.alpha.example.com/',NULL,'2026-10-09 23:39:45.575961',1,'{"redacted": 0, "kinds": [], "not_redacted": []}',2,'5d92b66b50ffd1a639a2e71c4039d53db9b945c34e66a618962a597ade6bd2cf','ale1:hBpiklYUQ1ugnX88y44MWD6RMAwl1F60USqWqdH+7wBiZ7BoLutXL7wjDmRbQwf5qnFykSv5QwVjomGb7/BN1RbrMZODpbF7rite5njVwMdqEuWsBnvGUVPoQCMpwkk=','agent');
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
INSERT INTO "gateway_requests" VALUES(1,'2026-10-09 23:39:45.580245',1,3,'agent','target','GET','https://shop.alpha.example.com/','shop.alpha.example.com',NULL,200,'allowed','',0,0,NULL,NULL,NULL);
INSERT INTO "gateway_requests" VALUES(2,'2026-10-09 23:39:45.580245',NULL,NULL,'dns','dns','DNS','refused.alpha.example.org','refused.alpha.example.org',NULL,NULL,'refused','not in scope alpha',0,0,NULL,NULL,NULL);
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
INSERT INTO "import_batches" VALUES(1,1,'har','Hand-made fixture 1.0','alpha.har','1bc91e30a4eb79ecf7b4eb3d30a2c40073a5a082374e64d37c14370e8261e625',5301,6,3,1,1,1,'[{"row": 5, "host": null, "reason": "unreadable", "detail": "no readable URL"}, {"row": 3, "host": "tracker.example.net", "reason": "out_of_scope", "detail": null}, {"row": 6, "host": "shop.alpha.example.com", "reason": "duplicate", "detail": null}]',1,'Olive alpha (owner-alpha@example.com)','2026-10-09 23:39:45.543824');
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
INSERT INTO "inbox_entries" VALUES(1,1,1,1,'har',NULL,'2026-10-09T10:00:00.000Z','shop.alpha.example.com','POST','https://shop.alpha.example.com/rest/user/login',200,'sign-in','ce51e55767af9fe3971d4e5ccfcb27f2c34866689b00785ecd1fec9e39a1ecd7','0fe2d1fc2d8226966bdc7c4bd9d41341fe7b578f76edcb714185ecbbfa30b635','056ccc8ec2a15f176a9ae161f6f3cb4fae3330fd51cd161bba28f09458021ee7','09ffbf88ea8026bb71f2448545eafac758977758638d4dcc2bef1a5cd7262fa1',271,182,'{"content_type": "application/json", "sets_cookie": true, "cors": false, "upgrade": "", "notes": ["raw bytes rebuilt from the export''s fields"]}','{"redacted": 6, "kinds": ["Cookie", "password", "email address", "Set-Cookie", "token"], "not_redacted": [], "counts": {"Cookie": 2, "password": 1, "email address": 1, "Set-Cookie": 1, "token": 1}}','mapped','[{"evidence_id": 3, "lane_id": 2, "item_idx": 1, "item_key": "BUG-BOUNTY-MAPPER-01", "by": 1, "by_name": "Olive alpha (owner-alpha@example.com)", "at": "2026-10-09T23:39:45.554035+00:00"}]',NULL,NULL,NULL,NULL,'2026-10-09 23:39:45.546239');
INSERT INTO "inbox_entries" VALUES(2,1,1,2,'har',NULL,'2026-10-09T10:00:01.000Z','shop.alpha.example.com','GET','https://shop.alpha.example.com/api/accounts/7?access_token=[redacted:sha256:b25d71ae7a97]&fields=name',403,NULL,'d4fc5e60454a55e46bf59582fcb31b43fcc685ecfe8f488fbe93332aa691f314','67ea03a67959591436af5a250f6f51071911f67cfc21691460dd3c772a389ec9','b11ff6f2bf746a201e397b9a974b5847356bc59841d5a0626374bd1430714b54','ea99780ab3953600e77927bbed45d138b86f9c4109f854d93d1d365468b096cc',219,77,'{"content_type": "application/json", "sets_cookie": false, "cors": false, "upgrade": "", "notes": ["raw bytes rebuilt from the export''s fields"]}','{"redacted": 4, "kinds": ["access_token", "Authorization", "X-Api-Key"], "not_redacted": [], "counts": {"access_token": 2, "Authorization": 1, "X-Api-Key": 1}}','dismissed','[]',1,'Olive alpha (owner-alpha@example.com)','2026-10-09 23:39:45.556856','noise alpha','2026-10-09 23:39:45.546240');
INSERT INTO "inbox_entries" VALUES(3,1,1,4,'har',NULL,'2026-10-09T10:00:03.000Z','shop.alpha.example.com','GET','https://shop.alpha.example.com/robots.txt',200,NULL,'d23d4a704cea6f1c8c747a3453abe3eb1df4663e94bc00dc41eb84e0e3be3312','e1ca07ca22813faaa046d5b9d9c57f1d29d0bf538f096b2b5c9ca18ca41a2e71','a9b35b9e247e363f8ce3965295a45cb2d9d712aa9a341c9d6251c26b406a1fad','c0585050ff5ffa7e9af08d2cc2ff69ab8d6c8cdfd783458cadd357b1f35635dc',28,74,'{"content_type": "text/plain", "sets_cookie": false, "cors": false, "upgrade": "", "notes": ["raw bytes rebuilt from the export''s fields"]}','{"redacted": 0, "kinds": [], "not_redacted": [], "counts": {}}','new','[]',NULL,NULL,NULL,NULL,'2026-10-09 23:39:45.546240');
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
INSERT INTO "jobs" VALUES(1,1,'resolve','["shop.alpha.example.com"]','done','',1,'7dcb150b7a43ef52e2e2b85fabf3b5e5544f0854969af0c100201dcc93dddc67','2026-10-09 23:39:45.389321','2026-10-09 23:39:45.391287','2026-10-09 23:39:45.405434',1,'null',0,NULL,NULL,1,NULL,NULL,'2026-10-09 23:39:45.400654',NULL);
INSERT INTO "jobs" VALUES(2,1,'wellknown','["https://shop.alpha.example.com/"]','done','',2,NULL,'2026-10-09 23:39:45.408422','2026-10-09 23:39:45.409749','2026-10-09 23:39:45.418472',1,'null',0,NULL,NULL,1,NULL,NULL,'2026-10-09 23:39:45.417497',NULL);
INSERT INTO "jobs" VALUES(3,1,'agent','["shop.alpha.example.com"]','running','',0,NULL,'2026-10-09 23:39:45.563061','2026-10-09 23:39:45.564994',NULL,0,NULL,0,2,'{"limits": {"max_turns": 15, "max_requests": 30, "max_cost_usd": 0.5}}',1,'6ac8a5550862dc314c112bfe84fb7ddba31f143df1eeed7dbd7292e864d783d3','631c678bf3d43a5e76b01da60c44dda500cc2ece2263c93571708fc2d7893d6c','2026-10-09 23:39:45.577267','driver alpha');
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
INSERT INTO "key_log" VALUES(1,1,2,'Rita alpha','2ae8e19906c979cf1cffc03abcd8ca7bd0f82e255b44ba6730e84f2b34fd44c5','Ed25519','registered','2026-10-09T23:39:45.503106+00:00','assigned_password','7bd84b19967dd2fd256b1c28f8bf6404eac41946716e9ebd51b6e686820fa49f','0000000000000000000000000000000000000000000000000000000000000000','6fa0267ca411ccf5ffc5695ed05ffacdc37a25628f1c753271bd4ac4fad0f651');
CREATE TABLE lanes (
	id INTEGER NOT NULL, 
	asset_id INTEGER NOT NULL, 
	role VARCHAR(32) NOT NULL, 
	opened_at DATETIME NOT NULL, executor VARCHAR(16) DEFAULT 'manual' NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(asset_id) REFERENCES assets (id), 
	UNIQUE (asset_id, role)
);
INSERT INTO "lanes" VALUES(1,1,'recon','2026-10-09 23:39:45.384396','manual');
INSERT INTO "lanes" VALUES(2,1,'mapper','2026-10-09 23:39:45.538927','agent');
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
INSERT INTO "leads" VALUES(1,1,2,'shop.alpha.example.com','https://shop.alpha.example.com/robots.txt','robots','robots names /private-alpha/','','','{}','d522137dd0cb7ca679d612616adcbbeedf8686300a7b3b1eb291cf0562aee2aa','2026-10-09 23:39:45.414061');
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
INSERT INTO "observations" VALUES(1,1,1,'shop.alpha.example.com','{"a": ["192.0.2.10"]}','2026-10-09 23:39:45.396698');
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
INSERT INTO "receipts" VALUES(1,1,'90728ca69fe07c2b1c8242c24621b1fb235685e7b732f6fdaba9009ee7d92d0d','2026-10-09 23:39:45.509645','Rita alpha',2,'{"chain":{"head":"d74da03e843ac71da65064395cfad216babc134d33863aaa1a7cc539cdb72ad4","seq":2},"engagement":{"id":1,"name":"Engagement alpha"},"format":"attackledger-receipt-v3","issued_at":"2026-10-09T23:39:45+00:00","key_fingerprint":"2ae8e19906c979cf1cffc03abcd8ca7bd0f82e255b44ba6730e84f2b34fd44c5","lane":{"host":"shop.alpha.example.com","id":1,"role":"recon"},"manifest_sha256":"90728ca69fe07c2b1c8242c24621b1fb235685e7b732f6fdaba9009ee7d92d0d","signer":{"email":"reviewer-alpha@example.com","id":2,"name":"Rita alpha"}}','FmFECQ7FzVlXrbtx3cBtnI4BrXa8U82cM+uNs4q2CgVqbEGoSci1OBRpAe81x3WgqDV2Z2/6yqN3IoHnQoZWCA==','Ed25519','MCowBQYDK2VwAyEA5Xw3WtF7IBtZH5yvQbxs3Fxt6YMS2HIhzfGiZHzTbRk=','2ae8e19906c979cf1cffc03abcd8ca7bd0f82e255b44ba6730e84f2b34fd44c5',NULL,NULL,NULL,NULL,'reviewer-alpha@example.com');
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
INSERT INTO "signing_keys" VALUES(1,2,'Ed25519','MCowBQYDK2VwAyEA5Xw3WtF7IBtZH5yvQbxs3Fxt6YMS2HIhzfGiZHzTbRk=','2ae8e19906c979cf1cffc03abcd8ca7bd0f82e255b44ba6730e84f2b34fd44c5','2026-10-09 23:39:45.502608',NULL);
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
INSERT INTO "test_accounts" VALUES(1,1,'A','customer alpha','["shop.alpha.example.com"]','cookie','["Cookie"]','ale1:eIBmN+BU/knDTgr5roGi3rtxg+RCBWUcPrfBzaWdfOerhHnUUKptF/QT8dZ0poWA4L8FgJIwPCX6NMHLXKv2Dg==','e75c5c295ab7672483a130323c1e5e056cca8afd2739117de5d024f66630306c','2026-10-09 23:39:45.559911',1,NULL,NULL);
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
INSERT INTO "user_sessions" VALUES(1,'7d02410ffd3eaaeae0e75eb40335712564f1291d2c6ac986f792766241a593cc',1,'2026-10-09 23:39:45.309477','2026-10-10 11:39:45.309477');
INSERT INTO "user_sessions" VALUES(2,'3bf62edca57606a403759d22ad4f35900af7c6a238fe762a5ca4977de88aae58',2,'2026-10-09 23:39:45.498156','2026-10-10 11:39:45.498156');
INSERT INTO "user_sessions" VALUES(3,'b540b2c0c9965cbf610ec7b338bc7cf12ad089818fb7c675749de463ea37f816',1,'2026-10-09 23:39:45.535378','2026-10-10 11:39:45.535378');
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
INSERT INTO "users" VALUES(1,'owner-alpha@example.com','Olive alpha','scrypt$16384$8$1$e30f451aa7b4a389551b4d5663c9665c$2c343026160b9ab35e954683d0574b77dbbbd9d0c9c30c454507394459b1e96d',1,0,'2026-10-09 23:39:45.283223',0,'2026-10-09 23:39:45.535356','2026-10-09 23:39:45.309454');
INSERT INTO "users" VALUES(2,'reviewer-alpha@example.com','Rita alpha','scrypt$16384$8$1$3e4bd6badeba2ae444380586dab638b1$fe7d0bce1a0b298ead4fd5441e02fbaa3096bc4ce39e5311607da4067839d881',0,0,'2026-10-09 23:39:45.336670',0,'2026-10-09 23:39:45.498139',NULL);
INSERT INTO "users" VALUES(3,'viewer-alpha@example.com','Vic alpha','scrypt$16384$8$1$e245a89dc10e2ba60e5e6a82c53a8c5b$557a6c75e7eb6adaef439772f059def8ee43a5e20a21fa822102412c8bb3d265',0,0,'2026-10-09 23:39:45.361034',0,NULL,NULL);
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
INSERT INTO "write_proposals" VALUES(1,1,2,3,1,'POST','https://shop.alpha.example.com/api/basket','shop.alpha.example.com',NULL,'try alpha','ale1:i/NkmjDznThSEEmm40fgdFuWw/YguK0GqtYr9jdz92SQNKFaVMwlXT5Z7+mVwgFI8DnCZio1M74yyJT9aQfUuj9u2T63i96jFzj1EYqlPrj+OPzwYEOp5eEqvJnv5U6zxRI1ko9qcJTbZlKNhbXWAfnm4Ir2r8XN8ajwpkpKi/110qwM+xCY6bcZRGln','9e723b754769b24f1e070b7bf9f1131b521b2f960c22bda9906f3b4f572a8ce9','44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a','pending',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'2026-10-09 23:39:45.579411');
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
