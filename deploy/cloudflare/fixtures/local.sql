-- Fixture-only data. "fixture-test-key" is intentionally non-production and its SHA-256 is known.
INSERT INTO users VALUES ('1001','active','user',1,'1000000','["2001"]',0,'2026-09-06T00:00:00Z');
INSERT INTO users VALUES ('1002','disabled','user',1,'1000000','[]',0,'2026-09-06T00:00:00Z');
INSERT INTO groups VALUES ('2001','fixture-group','openai','active',0,'payg','2026-09-06T00:00:00Z');
INSERT INTO api_keys VALUES ('3001','1001','2001','fixture active','active','40829bc3c826ce7293feb726994f7f21b24d66e85f4f79e3696e994b9047853c','[]','[]',NULL,NULL,'2026-09-06T00:00:00Z');
INSERT INTO api_keys VALUES ('3002','1002','2001','fixture disabled user','active','e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855','[]','[]',NULL,NULL,'2026-09-06T00:00:00Z');
INSERT INTO accounts VALUES ('4001','fixture mock','openai','openai','active',1,10,1,'fixture:v1:mock-upstream','{}','2026-09-06T00:00:00Z');
INSERT INTO account_groups VALUES ('4001','2001');
INSERT INTO model_aliases VALUES ('fixture-model','mock-upstream-model','active','2026-09-06T00:00:00Z');
