import json
import pandas as pd
import numpy as np
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import re
from urllib.parse import urlparse
import sqlite3
import base64
import os
import zipfile
import shutil
from sentence_transformers import SentenceTransformer
from sklearn.cluster import DBSCAN
import ollama
class CampaignHistory:

    def __init__(self, db_path: str='campaign_history.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('\n            CREATE TABLE IF NOT EXISTS campaigns (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                campaign_name TEXT,\n                centroid_embedding BLOB,\n                ioc_sender_domains TEXT,\n                ioc_url_domains TEXT,\n                ioc_url_paths TEXT,\n                ioc_subject_patterns TEXT,\n                attack_tags TEXT,\n                first_seen TEXT,\n                last_seen TEXT,\n                email_count INTEGER,\n                created_at TEXT DEFAULT CURRENT_TIMESTAMP\n            )\n        ')
        conn.commit()
        conn.close()

    def store_campaign(self, campaign_name: str, centroid_embedding: np.ndarray, iocs: Dict, attack_tags: List[str], date_range: Tuple[str, str], email_count: int) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        centroid_embedding = centroid_embedding.astype(np.float32)
        embedding_blob = base64.b64encode(json.dumps({'shape': list(centroid_embedding.shape), 'dtype': str(centroid_embedding.dtype), 'data': base64.b64encode(centroid_embedding.tobytes()).decode('utf-8')}).encode('utf-8')).decode('utf-8')
        cursor.execute('\n            INSERT INTO campaigns (campaign_name, centroid_embedding, ioc_sender_domains,\n                                 ioc_url_domains, ioc_url_paths, ioc_subject_patterns,\n                                 attack_tags, first_seen, last_seen, email_count)\n            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n        ', (campaign_name, embedding_blob, json.dumps(iocs.get('sender_domains', [])), json.dumps(iocs.get('url_domains', [])), json.dumps(iocs.get('url_paths', [])), json.dumps(iocs.get('subject_patterns', [])), json.dumps(attack_tags), date_range[0], date_range[1], email_count))
        campaign_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return campaign_id

    def find_recurrence(self, centroid_embedding: np.ndarray, similarity_threshold: float=0.85) -> Optional[Dict]:
        if centroid_embedding.dtype != np.float32:
            centroid_embedding = centroid_embedding.astype(np.float32)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id, campaign_name, centroid_embedding, first_seen, last_seen, email_count FROM campaigns')
        best_match = None
        best_similarity = 0.0
        for row in cursor.fetchall():
            hist_id, hist_name, hist_embedding_blob, first_seen, last_seen, email_count = row
            embedding_json = json.loads(base64.b64decode(hist_embedding_blob).decode('utf-8'))
            dtype_str = embedding_json.get('dtype', 'float32')
            dtype = np.dtype(dtype_str)
            hist_embedding = np.frombuffer(base64.b64decode(embedding_json['data']), dtype=dtype).reshape(tuple(embedding_json['shape']))
            if hist_embedding.dtype != np.float32:
                hist_embedding = hist_embedding.astype(np.float32)
            similarity = np.dot(centroid_embedding, hist_embedding) / (np.linalg.norm(centroid_embedding) * np.linalg.norm(hist_embedding))
            if similarity >= similarity_threshold and similarity > best_similarity:
                best_similarity = similarity
                best_match = {'id': hist_id, 'campaign_name': hist_name, 'similarity': float(similarity), 'first_seen': first_seen, 'last_seen': last_seen, 'email_count': email_count}
        conn.close()
        return best_match

    def update_campaign(self, campaign_id: int, last_seen: str, email_count: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('\n            UPDATE campaigns \n            SET last_seen = ?, email_count = email_count + ?\n            WHERE id = ?\n        ', (last_seen, email_count, campaign_id))
        conn.commit()
        conn.close()

class IOCExtractor:

    @staticmethod
    def extract_iocs(emails: List[Dict]) -> Dict:
        sender_domains = set()
        url_domains = set()
        url_paths = set()
        subject_patterns = []
        for email in emails:
            sender = email.get('sender', '')
            if '@' in sender:
                sender_domains.add(sender.split('@')[1].lower())
            url = email.get('url', '')
            if url:
                try:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        url_domains.add(parsed.netloc.lower())
                    if parsed.path:
                        url_paths.add(parsed.path)
                except:
                    pass
            subject = email.get('subject', '')
            if subject:
                normalized = re.sub('[^\\w\\s]', ' ', subject.lower())
                words = [w for w in normalized.split() if len(w) > 3]
                if words:
                    subject_patterns.append(' '.join(words[:5]))
        return {'sender_domains': sorted(list(sender_domains)), 'url_domains': sorted(list(url_domains)), 'url_paths': sorted(list(url_paths)), 'subject_patterns': list(set(subject_patterns))[:20]}

    @staticmethod
    def export_json(iocs: Dict, filename: str='iocs.json'):
        with open(filename, 'w') as f:
            json.dump(iocs, f, indent=2)
        return filename

    @staticmethod
    def export_csv(iocs: Dict, filename: str='iocs.csv'):
        rows = []
        for domain in iocs['sender_domains']:
            rows.append({'type': 'sender_domain', 'value': domain})
        for domain in iocs['url_domains']:
            rows.append({'type': 'url_domain', 'value': domain})
        for path in iocs['url_paths']:
            rows.append({'type': 'url_path', 'value': path})
        df = pd.DataFrame(rows)
        df.to_csv(filename, index=False)
        return filename

    @staticmethod
    def export_sigma(iocs: Dict, filename: str='iocs_sigma.yml'):
        sigma_rules = []
        if iocs['sender_domains']:
            domains_str = '|'.join(iocs['sender_domains'])
            sigma_rules.append(f'SenderDomain|contains|{domains_str}')
        if iocs['url_domains']:
            domains_str = '|'.join(iocs['url_domains'])
            sigma_rules.append(f'UrlDomain|contains|{domains_str}')
        sigma_content = f"title: Phishing Campaign IOCs\ndescription: Auto-extracted IOCs from phishing campaign analysis\nlogsource:\n    product: email\ndetection:\n    selection:\n        {chr(10).join(('        ' + rule for rule in sigma_rules))}\n    condition: selection\nlevel: high\n"
        with open(filename, 'w') as f:
            f.write(sigma_content)
        return filename

class ATTACKClassifier:
    TECHNIQUES = {'T1566.002': {'name': 'Phishing: Spearphishing Link', 'indicators': ['url', 'link', 'click', 'verify', 'login'], 'confidence_base': 0.7}, 'T1204.002': {'name': 'User Execution: Malicious File', 'indicators': ['attachment', 'download', 'file', 'document'], 'confidence_base': 0.6}, 'T1071.001': {'name': 'Application Layer Protocol: Web Protocols', 'indicators': ['http', 'https', 'url', 'domain'], 'confidence_base': 0.5}, 'T1583.001': {'name': 'Acquire Infrastructure: Domains', 'indicators': ['domain', 'dns', 'subdomain'], 'confidence_base': 0.6}, 'T1566': {'name': 'Phishing', 'indicators': ['urgent', 'verify', 'suspended', 'locked', 'security'], 'confidence_base': 0.8}}

    @staticmethod
    def classify_campaign(campaign_data: Dict) -> List[Dict]:
        techniques = []
        all_text = ' '.join([' '.join(campaign_data.get('sample_subjects', [])), ' '.join(campaign_data.get('unique_url_domains', [])), ' '.join(campaign_data.get('url_patterns', []))]).lower()
        for tech_id, tech_info in ATTACKClassifier.TECHNIQUES.items():
            confidence = tech_info['confidence_base']
            matched_indicators = []
            for indicator in tech_info['indicators']:
                if indicator in all_text:
                    matched_indicators.append(indicator)
                    confidence += 0.1
            if campaign_data.get('detected_brands') and tech_id in ['T1566', 'T1566.002']:
                confidence += 0.15
            urgency_count = campaign_data.get('urgency_keyword_usage', 0)
            if urgency_count > 0 and tech_id in ['T1566', 'T1566.002']:
                confidence += min(urgency_count * 0.05, 0.2)
            confidence = min(confidence, 1.0)
            if confidence >= 0.5:
                rationale = f"Matched indicators: {', '.join(matched_indicators[:3])}"
                if campaign_data.get('detected_brands'):
                    rationale += f". Brand impersonation: {', '.join(campaign_data['detected_brands'][:2])}"
                techniques.append({'technique_id': tech_id, 'technique_name': tech_info['name'], 'confidence': round(confidence, 2), 'rationale': rationale})
        techniques.sort(key=lambda x: x['confidence'], reverse=True)
        return techniques

class PhishingEmailAnalyzer:

    def __init__(self, model_name: str='all-MiniLM-L6-v2', ollama_model: str='llama2', enable_history: bool=True, db_path: str='campaign_history.db'):
        print('Loading Sentence Transformer model...')
        self.ollama_model = ollama_model
        self.enable_history = enable_history
        script_dir = os.path.dirname(os.path.abspath(__file__))
        local_zip_path = os.path.join(script_dir, f'{model_name}.zip')
        local_model_dir = os.path.join(script_dir, 'models', model_name)
        if os.path.exists(local_zip_path):
            print(f'[INFO] Found local model zip: {local_zip_path}')
            if not os.path.exists(local_model_dir):
                print(f'[INFO] Extracting model from zip file...')
                os.makedirs(os.path.dirname(local_model_dir), exist_ok=True)
                try:
                    temp_extract = os.path.join(script_dir, 'models', 'temp_extract')
                    if os.path.exists(temp_extract):
                        shutil.rmtree(temp_extract)
                    os.makedirs(temp_extract, exist_ok=True)
                    print(f'[INFO] Extracting zip file...')
                    with zipfile.ZipFile(local_zip_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_extract)
                    model_folder = None
                    root_path = os.path.join(temp_extract, 'root')
                    if os.path.exists(root_path):
                        temp_extract = root_path
                    for root, dirs, files in os.walk(temp_extract):
                        if 'snapshots' in root:
                            if any((f.endswith(('.json', '.safetensors', '.bin')) for f in files)):
                                has_config = any(('config.json' in f or 'sentence_bert_config.json' in f for f in files))
                                has_model = any((f.endswith(('.safetensors', '.bin')) for f in files))
                                if has_config and has_model:
                                    model_folder = root
                                    break
                    if not model_folder:
                        for root, dirs, files in os.walk(temp_extract):
                            if any((f.endswith(('.json', '.safetensors', '.bin')) for f in files)):
                                has_config = any(('config.json' in f or 'sentence_bert_config.json' in f for f in files))
                                has_model = any((f.endswith(('.safetensors', '.bin')) for f in files))
                                if has_config and has_model:
                                    model_folder = root
                                    break
                    if model_folder:
                        if os.path.exists(local_model_dir):
                            shutil.rmtree(local_model_dir)
                        shutil.move(model_folder, local_model_dir)
                        print(f'[OK] Model extracted to: {local_model_dir}')
                        if os.path.exists(temp_extract):
                            try:
                                shutil.rmtree(temp_extract)
                            except:
                                pass
                    else:
                        raise Exception('Could not find model snapshot folder in zip archive. The zip should contain the Hugging Face cache structure.')
                except Exception as e:
                    print(f'[ERROR] Failed to extract zip file: {e}')
                    import traceback
                    traceback.print_exc()
                    print(f"[INFO] Please check that '{local_zip_path}' is a valid zip file")
                    raise Exception(f'Failed to extract model from zip file: {e}')
            if os.path.exists(local_model_dir):
                try:
                    print(f'[INFO] Loading model from local directory: {local_model_dir}')
                    self.embedding_model = SentenceTransformer(local_model_dir)
                    print(f"[OK] Model '{model_name}' loaded from local zip file!")
                    if enable_history:
                        self.campaign_history = CampaignHistory(db_path)
                        print(f'[OK] Campaign history enabled (DB: {db_path})')
                    self._init_ollama()
                    return
                except Exception as e:
                    print(f'[ERROR] Failed to load model from local directory: {e}')
                    print(f'[INFO] Model directory exists at: {local_model_dir}')
                    print(f'[INFO] Please verify the model files are complete and valid')
                    raise Exception(f'Failed to load model from local directory: {e}')
            else:
                raise Exception(f'Model directory not found after extraction. Expected: {local_model_dir}')
        else:
            print(f'[ERROR] Local model zip file not found: {local_zip_path}')
            print(f'[INFO] OFFLINE MODE: This application requires a local model zip file.')
            print(f"[INFO] Please ensure '{model_name}.zip' is in the project directory:")
            print(f'[INFO]   Project directory: {script_dir}')
            print(f'[INFO]   Expected file: {local_zip_path}')
            raise Exception(f"OFFLINE MODE: Local model zip file '{model_name}.zip' not found in {script_dir}. Cannot download due to corporate network restrictions.")

    def _init_ollama(self):
        print('Checking Ollama connection...')
        try:
            models_response = ollama.list()
            if hasattr(models_response, 'models'):
                model_list = models_response.models
            elif isinstance(models_response, dict) and 'models' in models_response:
                model_list = models_response['models']
            elif isinstance(models_response, list):
                model_list = models_response
            else:
                model_list = []
            model_names = []
            for m in model_list:
                if hasattr(m, 'model'):
                    model_names.append(m.model)
                elif hasattr(m, 'name'):
                    model_names.append(m.name)
                elif isinstance(m, dict):
                    model_names.append(m.get('model', m.get('name', '')))
                else:
                    model_names.append(str(m))
            model_found = any((self.ollama_model in name or f'{self.ollama_model}:latest' in name or name.startswith(self.ollama_model + ':') or (name == self.ollama_model) for name in model_names))
            if not model_found and model_names:
                print(f"[ERROR] Model '{self.ollama_model}' not found!")
                print(f'  Available models: {model_names}')
                print(f'  Please run: ollama pull {self.ollama_model}')
                raise Exception(f'Model {self.ollama_model} not available')
            elif not model_names:
                print(f'[WARNING] No models found. Please run: ollama pull {self.ollama_model}')
                print(f'[INFO] Proceeding anyway - will attempt to use {self.ollama_model}')
            print(f'[OK] Ollama connected (using model: {self.ollama_model})')
            self.ollama_available = True
        except Exception as e:
            print(f'[ERROR] Ollama connection failed: {e}')
            print('\n[REQUIRED] Ollama must be running for LLM analysis!')
            print('  Steps:')
            print('  1. Install Ollama from https://ollama.ai')
            print(f'  2. Run: ollama pull {self.ollama_model}')
            print('  3. Ensure Ollama service is running')
            raise Exception(f'Ollama is required but not available: {e}')

    def extract_domain(self, email: str) -> str:
        if '@' in email:
            return email.split('@')[1].lower()
        return email.lower()

    def extract_url_domain(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            return domain.lower()
        except:
            return url.lower()

    def detect_brand_in_text(self, text: str) -> List[str]:
        brands = ['bank of america', 'chase', 'wells fargo', 'citibank', 'paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix', 'linkedin', 'facebook', 'twitter', 'instagram', 'dropbox', 'dhl', 'fedex', 'ups']
        text_lower = text.lower()
        detected = [brand for brand in brands if brand in text_lower]
        return detected

    def prepare_embeddings(self, emails: List[Dict]) -> Tuple[np.ndarray, List[str]]:
        print('Creating embeddings...')
        subjects = [email.get('subject', '') for email in emails]
        senders = [email.get('sender', '') for email in emails]
        urls = [email.get('url', '') for email in emails]
        subject_embeddings = self.embedding_model.encode(subjects, show_progress_bar=False)
        url_embeddings = self.embedding_model.encode(urls, show_progress_bar=False)
        sender_domains = [self.extract_domain(sender) for sender in senders]
        url_domains = [self.extract_url_domain(url) for url in urls]
        sender_domain_embeddings = self.embedding_model.encode(sender_domains, show_progress_bar=False)
        url_domain_embeddings = self.embedding_model.encode(url_domains, show_progress_bar=False)
        combined_embeddings = np.hstack([subject_embeddings, url_embeddings, sender_domain_embeddings, url_domain_embeddings])
        return (combined_embeddings, subjects)

    def cluster_emails(self, embeddings: np.ndarray, eps: float=0.5, min_samples: int=3) -> np.ndarray:
        print('Clustering emails with DBSCAN...')
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms[norms == 0] = 1
        embeddings_normalized = embeddings / norms
        clustering = DBSCAN(eps=eps, min_samples=min_samples, metric='cosine')
        cluster_labels = clustering.fit_predict(embeddings_normalized)
        n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
        n_noise = list(cluster_labels).count(-1)
        print(f'  Found {n_clusters} clusters, {n_noise} noise points')
        return cluster_labels

    def analyze_campaign_features(self, cluster_emails: List[Dict], cluster_id: int) -> Dict:
        if not cluster_emails:
            return {}
        subjects = [e.get('subject', '') for e in cluster_emails]
        senders = [e.get('sender', '') for e in cluster_emails]
        urls = [e.get('url', '') for e in cluster_emails]
        dates = [e.get('date', '') for e in cluster_emails]
        sender_domains = [self.extract_domain(s) for s in senders]
        url_domains = [self.extract_url_domain(u) for u in urls]
        unique_sender_domains = list(set(sender_domains))
        unique_url_domains = list(set(url_domains))
        all_text = ' '.join(subjects + urls)
        detected_brands = self.detect_brand_in_text(all_text)
        url_patterns = []
        for url in urls:
            if url:
                parsed = urlparse(url)
                path = parsed.path
                if path:
                    url_patterns.append(path)
        urgency_keywords = ['urgent', 'immediate', 'verify', 'suspended', 'locked', 'expired', 'action required', 'security alert', 'confirm']
        urgency_count = sum((1 for s in subjects if any((kw in s.lower() for kw in urgency_keywords))))
        return {'email_count': len(cluster_emails), 'unique_sender_domains': unique_sender_domains, 'unique_url_domains': unique_url_domains, 'detected_brands': list(set(detected_brands)), 'url_patterns': list(set(url_patterns))[:5], 'urgency_keyword_usage': urgency_count, 'date_range': self._get_date_range(dates), 'sample_subjects': list(set(subjects))[:5], 'sample_urls': list(set(urls))[:5]}

    def _get_date_range(self, dates: List[str]) -> Tuple[str, str]:
        valid_dates = []
        for date_str in dates:
            try:
                if isinstance(date_str, str):
                    for fmt in ['%Y-%m-%d', '%Y/%m/%d', '%m/%d/%Y', '%d/%m/%Y']:
                        try:
                            valid_dates.append(datetime.strptime(date_str, fmt))
                            break
                        except:
                            continue
            except:
                continue
        if valid_dates:
            return (min(valid_dates).strftime('%Y-%m-%d'), max(valid_dates).strftime('%Y-%m-%d'))
        return ('Unknown', 'Unknown')

    def generate_llm_insights(self, campaign_data: Dict) -> Dict:
        if not self.ollama_available:
            raise Exception('Ollama LLM is REQUIRED but not available. Please ensure Ollama is running and model is downloaded.')
        prompt = f"Analyze this phishing email campaign and provide:\n1. A descriptive campaign name\n2. Threat intelligence (targets, techniques, attack patterns)\n3. Correlation logic explanation\n4. Recommended mitigation steps\n\nCampaign Data:\n- Emails: {campaign_data['email_count']}\n- Sender Domains: {', '.join(campaign_data['unique_sender_domains'][:5])}\n- URL Domains: {', '.join(campaign_data['unique_url_domains'][:5])}\n- Detected Brands: {', '.join(campaign_data['detected_brands'])}\n- Urgency Keywords Used: {campaign_data['urgency_keyword_usage']} emails\n- Sample Subjects: {', '.join(campaign_data['sample_subjects'][:3])}\n- URL Patterns: {', '.join(campaign_data['url_patterns'][:3])}\n\nProvide a structured analysis in JSON format with fields: campaign_name, threat_intelligence, correlation_logic, mitigation_steps."
        try:
            response = ollama.generate(model=self.ollama_model, prompt=prompt)
            response_text = response['response']
            json_match = re.search('\\{.*\\}', response_text, re.DOTALL)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                    return parsed
                except:
                    pass
            return {'campaign_name': self._extract_campaign_name(response_text), 'threat_intelligence': response_text, 'correlation_logic': 'Generated by LLM analysis', 'mitigation_steps': self._extract_mitigation_steps(response_text)}
        except Exception as e:
            print(f'  [WARNING] LLM analysis failed: {e}')
            return {'campaign_name': 'Phishing Campaign', 'threat_intelligence': f'LLM analysis error: {str(e)}', 'correlation_logic': 'Analysis based on clustering', 'mitigation_steps': ['Block sender domains', 'Alert users']}

    def _extract_campaign_name(self, text: str) -> str:
        patterns = ['Campaign[:\\s]+["\\\']?([^"\\\'\\n]+)["\\\']?', 'campaign name[:\\s]+["\\\']([^"\\\'\\n]+)', '["\\\']([^"\\\']+Phishing[^"\\\']+)["\\\']']
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return 'Phishing Campaign'

    def _extract_mitigation_steps(self, text: str) -> List[str]:
        steps = []
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if re.match('^[\\d\\-]\\s+', line) or 'mitigation' in line.lower():
                step = re.sub('^[\\d\\-]\\s+', '', line)
                if step and len(step) > 10:
                    steps.append(step)
        return steps[:5] if steps else ['Block sender domains', 'Alert users', 'Monitor patterns']

    def calculate_confidence(self, campaign_data: Dict) -> float:
        score = 0.0
        email_count = campaign_data['email_count']
        score += min(email_count / 50.0, 0.3) * 100
        if campaign_data['detected_brands']:
            score += 20.0
        urgency_ratio = campaign_data['urgency_keyword_usage'] / email_count if email_count > 0 else 0
        score += min(urgency_ratio * 30, 30.0)
        sender_domain_count = len(campaign_data['unique_sender_domains'])
        if sender_domain_count <= 3:
            score += 15.0
        elif sender_domain_count <= 5:
            score += 10.0
        if campaign_data['url_patterns']:
            score += 15.0
        return min(score, 100.0)

    def find_similar_emails(self, user_input: str, input_type: str, all_emails: List[Dict], similarity_threshold: float=0.6, max_results: int=100) -> List[Dict]:
        print(f'\nSearching for emails similar to {input_type}: {user_input[:50]}...')
        input_embedding = self.embedding_model.encode([user_input], show_progress_bar=False)[0]
        similar_emails = []
        similarities = []
        if input_type == 'sender':
            user_domain = self.extract_domain(user_input)
            user_domain_embedding = self.embedding_model.encode([user_domain], show_progress_bar=False)[0]
            for email in all_emails:
                email_domain = self.extract_domain(email.get('sender', ''))
                if user_domain == email_domain:
                    similar_emails.append(email)
                    similarities.append(1.0)
                else:
                    domain_embedding = self.embedding_model.encode([email_domain], show_progress_bar=False)[0]
                    similarity = np.dot(user_domain_embedding, domain_embedding) / (np.linalg.norm(user_domain_embedding) * np.linalg.norm(domain_embedding))
                    if similarity >= similarity_threshold:
                        similar_emails.append(email)
                        similarities.append(similarity)
        elif input_type == 'subject':
            for email in all_emails:
                subject = email.get('subject', '')
                if not subject:
                    continue
                subject_embedding = self.embedding_model.encode([subject], show_progress_bar=False)[0]
                similarity = np.dot(input_embedding, subject_embedding) / (np.linalg.norm(input_embedding) * np.linalg.norm(subject_embedding))
                if similarity >= similarity_threshold:
                    similar_emails.append(email)
                    similarities.append(similarity)
        elif input_type == 'url':
            user_domain = self.extract_url_domain(user_input)
            user_domain_embedding = self.embedding_model.encode([user_domain], show_progress_bar=False)[0]
            for email in all_emails:
                url = email.get('url', '')
                if not url:
                    continue
                email_domain = self.extract_url_domain(url)
                if user_domain == email_domain:
                    similar_emails.append(email)
                    similarities.append(1.0)
                else:
                    domain_embedding = self.embedding_model.encode([email_domain], show_progress_bar=False)[0]
                    domain_similarity = np.dot(user_domain_embedding, domain_embedding) / (np.linalg.norm(user_domain_embedding) * np.linalg.norm(domain_embedding))
                    url_embedding = self.embedding_model.encode([url], show_progress_bar=False)[0]
                    url_similarity = np.dot(input_embedding, url_embedding) / (np.linalg.norm(input_embedding) * np.linalg.norm(url_embedding))
                    similarity = max(domain_similarity, url_similarity)
                    if similarity >= similarity_threshold:
                        similar_emails.append(email)
                        similarities.append(similarity)
        if similar_emails:
            sorted_indices = np.argsort(similarities)[::-1]
            sorted_emails = [similar_emails[i] for i in sorted_indices[:max_results]]
            print(f'  Found {len(sorted_emails)} similar emails (threshold: {similarity_threshold})')
            return sorted_emails
        else:
            print(f'  No similar emails found (threshold: {similarity_threshold})')
            return []

    def analyze(self, emails: List[Dict], eps: float=0.5, min_samples: int=3, recurrence_threshold: float=0.85) -> List[Dict]:
        self.recurrence_threshold = recurrence_threshold
        print(f"\n{'=' * 60}")
        print('PHISHING EMAIL CAMPAIGN ANALYSIS')
        print(f"{'=' * 60}\n")
        print(f'Analyzing {len(emails)} emails...\n')
        embeddings, subjects = self.prepare_embeddings(emails)
        cluster_labels = self.cluster_emails(embeddings, eps=eps, min_samples=min_samples)
        campaigns = []
        unique_clusters = set(cluster_labels)
        unique_clusters.discard(-1)
        for cluster_id in sorted(unique_clusters):
            cluster_indices = [i for i, label in enumerate(cluster_labels) if label == cluster_id]
            cluster_emails = [emails[i] for i in cluster_indices]
            print(f'\nAnalyzing Cluster {cluster_id} ({len(cluster_emails)} emails)...')
            campaign_data = self.analyze_campaign_features(cluster_emails, cluster_id)
            confidence = self.calculate_confidence(campaign_data)
            print('  Generating LLM insights...')
            llm_insights = self.generate_llm_insights(campaign_data)
            print('  Extracting IOCs...')
            iocs = IOCExtractor.extract_iocs(cluster_emails)
            print('  Classifying ATT&CK techniques...')
            attack_techniques = ATTACKClassifier.classify_campaign(campaign_data)
            attack_tags = [t['technique_id'] for t in attack_techniques]
            recurrence_info = None
            campaign_id = None
            is_recurrence = False
            if self.enable_history:
                print('  Checking campaign history...')
                cluster_embeddings = embeddings[cluster_indices]
                centroid = np.mean(cluster_embeddings, axis=0)
                centroid = centroid.astype(np.float32)
                centroid = centroid / np.linalg.norm(centroid)
                recurrence = self.campaign_history.find_recurrence(centroid, similarity_threshold=self.recurrence_threshold)
                if recurrence:
                    is_recurrence = True
                    recurrence_info = recurrence
                    campaign_id = recurrence['id']
                    print(f"  [RECURRENCE] Matched existing campaign #{campaign_id} (similarity: {recurrence['similarity']:.2%})")
                    self.campaign_history.update_campaign(campaign_id, campaign_data['date_range'][1], campaign_data['email_count'])
                else:
                    campaign_name = llm_insights.get('campaign_name', 'Phishing Campaign')
                    campaign_id = self.campaign_history.store_campaign(campaign_name, centroid, iocs, attack_tags, campaign_data['date_range'], campaign_data['email_count'])
                    print(f'  [NEW CAMPAIGN] Stored as campaign #{campaign_id}')
            campaign_result = {'cluster_id': int(cluster_id), 'campaign_id': campaign_id, 'campaign_name': llm_insights.get('campaign_name', 'Phishing Campaign'), 'confidence': round(confidence, 1), 'email_count': campaign_data['email_count'], 'date_range': campaign_data['date_range'], 'threat_intelligence': llm_insights.get('threat_intelligence', ''), 'correlation_logic': llm_insights.get('correlation_logic', ''), 'mitigation_steps': llm_insights.get('mitigation_steps', []), 'campaign_data': campaign_data, 'iocs': iocs, 'attack_techniques': attack_techniques, 'is_recurrence': is_recurrence, 'recurrence_info': recurrence_info}
            campaigns.append(campaign_result)
        return campaigns

    def print_results(self, campaigns: List[Dict]):
        print(f"\n{'=' * 60}")
        print('CAMPAIGN ANALYSIS RESULTS')
        print(f"{'=' * 60}\n")
        for i, campaign in enumerate(campaigns, 1):
            print(f"\n{'-' * 60}")
            print(f"Campaign {i}: {campaign['campaign_name']}")
            print(f"{'-' * 60}")
            print(f"Confidence: {campaign['confidence']}%")
            print(f"Emails: {campaign['email_count']}")
            print(f"Time Range: {campaign['date_range'][0]} to {campaign['date_range'][1]}")
            print(f'\nThreat Intelligence:')
            threat_intel = campaign['threat_intelligence']
            if isinstance(threat_intel, str):
                print(f'  {threat_intel[:500]}...')
            else:
                print(f'  {threat_intel}')
            print(f'\nCorrelation Logic:')
            print(f"  {campaign['correlation_logic']}")
            print(f'\nRecommended Actions:')
            for step in campaign['mitigation_steps']:
                print(f'  - {step}')
            data = campaign['campaign_data']
            print(f'\nDetails:')
            print(f"  - Sender Domains: {len(data['unique_sender_domains'])} unique")
            print(f"  - URL Domains: {len(data['unique_url_domains'])} unique")
            if data['detected_brands']:
                print(f"  - Detected Brands: {', '.join(data['detected_brands'])}")
            if data['url_patterns']:
                print(f"  - URL Patterns: {', '.join(data['url_patterns'][:3])}")
            if campaign.get('is_recurrence'):
                rec_info = campaign.get('recurrence_info', {})
                print(f'\n[FEATURE 1] Campaign History:')
                print(f"  - Status: RECURRENCE (Campaign #{campaign.get('campaign_id')})")
                print(f"  - Similarity: {rec_info.get('similarity', 0):.2%}")
                print(f"  - First Seen: {rec_info.get('first_seen', 'Unknown')}")
                print(f"  - Last Seen: {rec_info.get('last_seen', 'Unknown')}")
            elif campaign.get('campaign_id'):
                print(f'\n[FEATURE 1] Campaign History:')
                print(f"  - Status: NEW CAMPAIGN (ID: #{campaign.get('campaign_id')})")
            if campaign.get('attack_techniques'):
                print(f'\n[FEATURE 2] MITRE ATT&CK Techniques:')
                for tech in campaign['attack_techniques'][:3]:
                    print(f"  - {tech['technique_id']}: {tech['technique_name']} (confidence: {tech['confidence']:.0%})")
                    print(f"    Rationale: {tech['rationale']}")
            if campaign.get('iocs'):
                iocs = campaign['iocs']
                print(f'\n[FEATURE 3] Extracted IOCs:')
                print(f"  - Sender Domains: {len(iocs.get('sender_domains', []))}")
                print(f"  - URL Domains: {len(iocs.get('url_domains', []))}")
                print(f"  - URL Paths: {len(iocs.get('url_paths', []))}")
                if iocs.get('sender_domains'):
                    print(f"    Sample: {', '.join(iocs['sender_domains'][:3])}")

def _csv_cell(row: pd.Series, *column_names: str) -> str:
    for name in column_names:
        if name not in row.index:
            continue
        val = row[name]
        if pd.isna(val):
            continue
        return str(val).strip()
    return ''

def emails_from_dataframe(df: pd.DataFrame) -> List[Dict]:
    emails = []
    for _, row in df.iterrows():
        email = {'sender': _csv_cell(row, 'SenderFromAddress', 'sender'), 'subject': _csv_cell(row, 'Subject', 'subject'), 'url': _csv_cell(row, 'Url', 'url'), 'date': _csv_cell(row, 'TimeGenerated', 'date')}
        nm = _csv_cell(row, 'NetworkMessageId')
        if nm:
            email['network_message_id'] = nm
        emails.append(email)
    return emails

def load_emails_from_csv(filepath: str) -> List[Dict]:
    df = pd.read_csv(filepath)
    return emails_from_dataframe(df)

def create_sample_data() -> List[Dict]:
    return [{'sender': 'security@fake-bank.com', 'subject': 'URGENT: Verify your Bank of America account', 'url': 'https://fake-bank.com/login?verify=123', 'date': '2024-01-15'}, {'sender': 'noreply@malicious.com', 'subject': 'Action Required: Chase account suspended', 'url': 'https://fake-bank.com/login?verify=456', 'date': '2024-01-16'}, {'sender': 'alert@malicious.net', 'subject': 'URGENT: Bank of America security alert', 'url': 'https://fake-bank.com/login?verify=789', 'date': '2024-01-17'}, {'sender': 'support@phishing-site.com', 'subject': 'Your PayPal account needs verification', 'url': 'https://paypal-fake.com/verify', 'date': '2024-01-18'}, {'sender': 'service@phishing-site.com', 'subject': 'PayPal account locked - verify now', 'url': 'https://paypal-fake.com/verify', 'date': '2024-01-19'}]
if __name__ == '__main__':
    analyzer = PhishingEmailAnalyzer(model_name='all-MiniLM-L6-v2', ollama_model='llama2')
    print('\n' + '=' * 60)
    print('Loading email dataset...')
    print('=' * 60)
    try:
        all_emails = load_emails_from_csv('sample_emails.csv')
        print(f'[OK] Loaded {len(all_emails)} emails from sample_emails.csv')
    except FileNotFoundError:
        all_emails = create_sample_data()
        print(f'[OK] Using {len(all_emails)} sample emails')
    print('\n' + '=' * 60)
    print('PHISHING EMAIL CORRELATION ANALYSIS')
    print('=' * 60)
    print('\nPlease provide ONE of the following:')
    print('1. Sender address (e.g., security@fake-bank.com)')
    print('2. Subject line (e.g., URGENT: Verify your account)')
    print('3. URL (e.g., https://fake-bank.com/login)')
    print('\nThe system will find similar emails and correlate them into campaigns.')
    while True:
        print('\n' + '-' * 60)
        input_type = input("\nEnter input type (sender/subject/url) or 'quit' to exit: ").strip().lower()
        if input_type == 'quit':
            print('\nExiting...')
            break
        if input_type not in ['sender', 'subject', 'url']:
            print("[ERROR] Please enter 'sender', 'subject', or 'url'")
            continue
        user_input = input(f'Enter {input_type}: ').strip()
        if not user_input:
            print('[ERROR] Input cannot be empty')
            continue
        similarity_threshold = 0.5
        similar_emails = analyzer.find_similar_emails(user_input=user_input, input_type=input_type, all_emails=all_emails, similarity_threshold=similarity_threshold, max_results=100)
        if not similar_emails:
            print('\n[INFO] No similar emails found. Try lowering the similarity threshold or check your input.')
            continue
        print(f'\nAnalyzing {len(similar_emails)} correlated emails...')
        campaigns = analyzer.analyze(similar_emails, eps=0.5, min_samples=2)
        analyzer.print_results(campaigns)
        output_file = f'campaign_analysis_{input_type}_{len(campaigns)}.json'
        with open(output_file, 'w') as f:
            json.dump(campaigns, f, indent=2, default=str)
        print(f'\n[OK] Analysis complete! Results saved to {output_file}')
        print('\n[FEATURE 3] Exporting IOCs...')
        all_iocs = {'sender_domains': set(), 'url_domains': set(), 'url_paths': set(), 'subject_patterns': []}
        for campaign in campaigns:
            if campaign.get('iocs'):
                iocs = campaign['iocs']
                all_iocs['sender_domains'].update(iocs.get('sender_domains', []))
                all_iocs['url_domains'].update(iocs.get('url_domains', []))
                all_iocs['url_paths'].update(iocs.get('url_paths', []))
                all_iocs['subject_patterns'].extend(iocs.get('subject_patterns', []))
        consolidated_iocs = {'sender_domains': sorted(list(all_iocs['sender_domains'])), 'url_domains': sorted(list(all_iocs['url_domains'])), 'url_paths': sorted(list(all_iocs['url_paths'])), 'subject_patterns': sorted(list(set(all_iocs['subject_patterns'])))[:50]}
        json_file = IOCExtractor.export_json(consolidated_iocs, f'iocs_{input_type}.json')
        csv_file = IOCExtractor.export_csv(consolidated_iocs, f'iocs_{input_type}.csv')
        sigma_file = IOCExtractor.export_sigma(consolidated_iocs, f'iocs_{input_type}_sigma.yml')
        print(f'  - JSON: {json_file}')
        print(f'  - CSV: {csv_file}')
        print(f'  - Sigma: {sigma_file}')
        continue_analysis = input('\nAnalyze another input? (y/n): ').strip().lower()
        if continue_analysis != 'y':
            break
