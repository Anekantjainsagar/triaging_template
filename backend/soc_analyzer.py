import os
import re
import warnings
import pandas as pd
from typing import Dict, List

warnings.filterwarnings("ignore")

# NLP and ML imports
try:
    import nltk
    from sklearn.cluster import KMeans
    from nltk.stem import WordNetLemmatizer
    from sklearn.feature_extraction.text import TfidfVectorizer

    nltk.download("punkt", quiet=True)
    nltk.download("stopwords", quiet=True)
    nltk.download("wordnet", quiet=True)

    NLP_AVAILABLE = True
except ImportError:
    print(
        "⚠️  Advanced NLP libraries not found. Install with: pip install scikit-learn nltk"
    )
    NLP_AVAILABLE = False

# Ollama integration
try:
    import ollama

    OLLAMA_AVAILABLE = True
except ImportError:
    print("⚠️  Ollama not found. Install with: pip install ollama")
    OLLAMA_AVAILABLE = False


class IntelligentSOCAnalyzer:
    """Advanced SOC Tracker Analysis System with NLP and AI capabilities"""

    def __init__(
        self,
        data_directory="data",
        ollama_model="qwen2.5:0.5b",
    ):
        self.data_directory = data_directory
        self.ollama_model = ollama_model
        self.df = None

        # NLP components
        self.vectorizer = (
            TfidfVectorizer(
                max_features=1000, stop_words="english", ngram_range=(1, 3), min_df=2
            )
            if NLP_AVAILABLE
            else None
        )

        self.lemmatizer = WordNetLemmatizer() if NLP_AVAILABLE else None

        # Knowledge base for learning
        self.rule_patterns = {}
        self.incident_clusters = {}
        self.search_history = []
        self.performance_baselines = {}

    def load_and_process_data(self):
        """Load and intelligently process SOC tracker data"""
        print("🔄 Loading and processing SOC tracker data...")

        csv_files = []
        if os.path.exists(self.data_directory):
            csv_files = [
                f for f in os.listdir(self.data_directory) if f.endswith(".csv")
            ]

        if not csv_files:
            print(f"❌ No CSV files found in {self.data_directory}")
            return False

        combined_dfs = []
        for file in csv_files:
            file_path = os.path.join(self.data_directory, file)
            try:
                for encoding in ["utf-8", "latin1", "cp1252", "iso-8859-1"]:
                    try:
                        df = pd.read_csv(file_path, encoding=encoding)
                        df["source_file"] = file
                        combined_dfs.append(df)
                        print(f"✅ Loaded {file} ({len(df)} rows)")
                        break
                    except UnicodeDecodeError:
                        continue
            except Exception as e:
                print(f"❌ Error loading {file}: {e}")

        if not combined_dfs:
            return False

        # Combine and clean data
        self.df = pd.concat(combined_dfs, ignore_index=True)
        self._intelligent_data_cleaning()
        self._extract_patterns()

        print(f"✅ Successfully processed {len(self.df)} records")
        return True

    def _intelligent_data_cleaning(self):
        """Advanced data cleaning and preprocessing"""
        print("🧹 Performing intelligent data cleaning...")

        # Standardize column names
        column_mapping = {
            "RULE": ["RULE", "Rule", "rule", "Alert Rule", "Rule Name"],
            "Priority": ["Priority", "PRIORITY", "priority", "Severity"],
            "SHIFT": ["SHIFT", "Shift", "shift", "Shift Time"],
            "Status": ["Status", "STATUS", "status", "Incident Status"],
            "MTTD (Mins)": ["MTTD (Mins)", "MTTD", "Mean Time To Detect"],
            "MTTR    (Mins)": [
                "MTTR    (Mins)",
                "MTTR (Mins)",
                "MTTR",
                "Mean Time To Resolve",
            ],
            "Name of the Shift Engineer": [
                "Name of the Shift Engineer",
                "Engineer",
                "Assigned To",
            ],
            "False / True Positive": [
                "False / True Positive",
                "Classification",
                "FP/TP",
            ],
        }

        # Standardize columns
        for standard, variations in column_mapping.items():
            for var in variations:
                if var in self.df.columns and standard not in self.df.columns:
                    self.df[standard] = self.df[var]
                    break

        # Clean and standardize data
        if "RULE" in self.df.columns:
            self.df["RULE"] = self.df["RULE"].fillna("Unknown Rule")
            self.df["RULE_CLEAN"] = self.df["RULE"].apply(self._clean_rule_text)

        if "Priority" in self.df.columns:
            self.df["Priority"] = self.df["Priority"].str.upper().fillna("UNKNOWN")

        # Convert time columns
        time_columns = [
            "MTTD (Mins)",
            "MTTR    (Mins)",
            "Time To Breach SLA",
            "Remaining Mins to Breach",
        ]
        for col in time_columns:
            if col in self.df.columns:
                self.df[col] = pd.to_numeric(self.df[col], errors="coerce")

        # Parse dates
        if "Date" in self.df.columns:
            self.df["Date"] = pd.to_datetime(self.df["Date"], errors="coerce")
            self.df["Year"] = self.df["Date"].dt.year
            self.df["Month"] = self.df["Date"].dt.month
            self.df["DayOfWeek"] = self.df["Date"].dt.dayofweek

    def _clean_rule_text(self, rule_text):
        """Clean and normalize rule text for better matching - ENHANCED for rule numbers"""
        if pd.isna(rule_text):
            return ""

        text = str(rule_text).lower()
        original_text = text

        # Extract rule numbers (various formats)
        rule_number_patterns = [
            r"rule\s*#?\s*(\d+(?:[\/\-\.]\d+)*)",  # rule 286/2/002, rule#286, rule 123
            r"(\d+(?:[\/\-\.]\d+)+)",  # 286/2/002, 123-45-67
            r"rule\s*(\d+)",  # rule 286
        ]

        extracted_numbers = []
        for pattern in rule_number_patterns:
            matches = re.findall(pattern, original_text)
            extracted_numbers.extend(matches)

        # Clean text for general matching
        text = re.sub(r"rule#?\d+[-\s]*", "", text)
        text = re.sub(r"[^\w\s\/\-\.]", " ", text)  # Keep rule number separators
        text = " ".join(text.split())  # Normalize whitespace

        # Add extracted rule numbers back to the cleaned text for better matching
        if extracted_numbers:
            text = text + " " + " ".join(extracted_numbers)

        return text

    def _extract_patterns(self):
        """Extract intelligent patterns from the data for learning"""
        print("🧠 Extracting intelligent patterns...")

        if not NLP_AVAILABLE or "RULE" not in self.df.columns:
            return

        rule_texts = self.df["RULE_CLEAN"].dropna().unique()
        if len(rule_texts) > 0:
            try:
                self.rule_vectors = self.vectorizer.fit_transform(rule_texts)
                self.rule_texts = rule_texts

                # Cluster similar rules
                if len(rule_texts) > 5:
                    n_clusters = min(10, len(rule_texts) // 2)
                    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
                    clusters = kmeans.fit_predict(self.rule_vectors.toarray())

                    for i, cluster in enumerate(clusters):
                        if cluster not in self.incident_clusters:
                            self.incident_clusters[cluster] = []
                        self.incident_clusters[cluster].append(rule_texts[i])

                print(f"✅ Created embeddings for {len(rule_texts)} unique rules")
            except Exception as e:
                print(f"⚠️  Pattern extraction error: {e}")

    def get_rule_suggestions(self, query: str, top_k: int = 5) -> List[Dict]:
        """Get top 5 rule suggestions based on query - ENHANCED for rule numbers"""
        if self.df is None or "RULE" not in self.df.columns:
            return []

        query_clean = self._clean_rule_text(query)
        suggestions = []

        # Check if query contains rule numbers
        rule_number_patterns = [
            r"(\d+(?:[\/\-\.]\d+)+)",  # 286/2/002, 123-45-67
            r"rule\s*#?\s*(\d+)",  # rule 286, rule#286
            r"(\d{3,})",  # Any 3+ digit number
        ]

        query_has_rule_number = any(
            re.search(pattern, query, re.IGNORECASE) for pattern in rule_number_patterns
        )

        # Get unique rules
        unique_rules = (
            self.df["RULE"]
            .str.strip()
            .drop_duplicates()
            .dropna()
            .reset_index(drop=True)
        )

        # Further deduplicate by normalized rule text
        seen_normalized = set()
        final_unique_rules = []

        for rule in unique_rules:
            normalized = self._clean_rule_text(rule)
            if normalized not in seen_normalized and normalized.strip():
                seen_normalized.add(normalized)
                final_unique_rules.append(rule)

        for rule in final_unique_rules:
            rule_clean = self._clean_rule_text(rule)

            # Enhanced scoring for rule numbers
            if query_has_rule_number:
                rule_number_score = 0
                for pattern in rule_number_patterns:
                    query_numbers = re.findall(pattern, query, re.IGNORECASE)
                    rule_numbers = re.findall(pattern, rule, re.IGNORECASE)

                    for q_num in query_numbers:
                        for r_num in rule_numbers:
                            if q_num.lower() == r_num.lower():
                                rule_number_score = 1.0  # Perfect match
                            elif (
                                q_num.lower() in r_num.lower()
                                or r_num.lower() in q_num.lower()
                            ):
                                rule_number_score = max(
                                    rule_number_score, 0.8
                                )  # Partial match

                if rule_number_score > 0:
                    incident_count = len(self.df[self.df["RULE"] == rule])
                    suggestions.append(
                        {
                            "rule": rule,
                            "score": rule_number_score,
                            "incident_count": incident_count,
                            "match_type": "rule_number",
                        }
                    )
                    continue

            # Standard text similarity
            query_tokens = set(query_clean.split())
            rule_tokens = set(rule_clean.split())

            if query_tokens and rule_tokens:
                intersection = len(query_tokens.intersection(rule_tokens))
                union = len(query_tokens.union(rule_tokens))
                similarity = intersection / union if union > 0 else 0

                substring_score = 0
                for token in query_tokens:
                    if token in rule_clean:
                        substring_score += 1

                final_score = similarity + (substring_score / len(query_tokens) * 0.5)

                if final_score > 0.1:
                    incident_count = len(self.df[self.df["RULE"] == rule])
                    suggestions.append(
                        {
                            "rule": rule,
                            "score": final_score,
                            "incident_count": incident_count,
                            "match_type": "text_similarity",
                        }
                    )

        # Sort by score and return top k
        suggestions.sort(key=lambda x: (x["score"], x["incident_count"]), reverse=True)
        return suggestions[:top_k]
