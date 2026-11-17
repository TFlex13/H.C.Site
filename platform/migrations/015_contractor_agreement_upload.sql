BEGIN;
ALTER TABLE representative_documents DROP CONSTRAINT representative_documents_document_type_check;
ALTER TABLE representative_documents ADD CONSTRAINT representative_documents_document_type_check
CHECK (document_type IN ('id_front','id_back','w9','agreement'));
ALTER TABLE representative_document_access_audit DROP CONSTRAINT representative_document_access_audit_document_type_check;
ALTER TABLE representative_document_access_audit ADD CONSTRAINT representative_document_access_audit_document_type_check
CHECK (document_type IN ('id_front','id_back','w9','agreement'));
COMMIT;
