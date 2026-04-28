import streamlit as st
import joblib
import pandas as pd
import re
import os


# -----------------------------
# Page setup
# -----------------------------
st.set_page_config(
    page_title="Phishing Email Detection System",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------------
# Custom styling
# -----------------------------
st.markdown(
    """
    <style>
    .result-card {
        padding: 1.2rem;
        border-radius: 14px;
        margin-bottom: 1rem;
        border: 1px solid rgba(255,255,255,0.12);
        background-color: #161b22;
    }

    .phishing-card {
        border-left: 6px solid #ff4b4b;
        background-color: rgba(255, 75, 75, 0.12);
    }

    .legitimate-card {
        border-left: 6px solid #2ecc71;
        background-color: rgba(46, 204, 113, 0.12);
    }

    .neutral-card {
        border-left: 6px solid #4dabf7;
        background-color: rgba(77, 171, 247, 0.10);
    }

    .warning-card {
        border-left: 6px solid #f1c40f;
        background-color: rgba(241, 196, 15, 0.12);
    }

    .card-title {
        font-size: 1.15rem;
        font-weight: 700;
        margin-bottom: 0.4rem;
    }

    .card-value {
        font-size: 1.8rem;
        font-weight: 800;
        margin-bottom: 0.2rem;
    }

    .card-text {
        font-size: 0.95rem;
        line-height: 1.5;
        color: #d6d6d6;
    }

    .indicator-pill {
        display: inline-block;
        padding: 0.35rem 0.65rem;
        margin: 0.2rem 0.25rem 0.2rem 0;
        border-radius: 999px;
        background-color: rgba(255,255,255,0.10);
        border: 1px solid rgba(255,255,255,0.15);
        font-size: 0.85rem;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# -----------------------------
# Text cleaning function
# -----------------------------
def clean_text(text):
    """
    Cleans email text using the same preprocessing approach used during model training.
    """
    text = str(text).lower()

    text = re.sub(r"http\S+|www\S+|https\S+", " ", text)
    text = re.sub(r"\S+@\S+", " ", text)
    text = re.sub(r"\d+", " ", text)
    text = re.sub(r"[^a-zA-Z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    return text


# -----------------------------
# Suspicious indicator checker
# -----------------------------
def detect_suspicious_indicators(email_text):
    """
    Identifies common phishing-related language patterns.
    Returns a dictionary of detected indicator categories and matched words.
    """
    text_lower = email_text.lower()

    indicator_categories = {
        "Urgency language": [
            "urgent", "immediately", "act now", "as soon as possible",
            "limited time", "final warning"
        ],
        "Account or login request": [
            "login", "account", "verify", "password", "credentials",
            "confirm your identity"
        ],
        "Threat or consequence": [
            "suspended", "closed", "terminated", "permanent",
            "restricted", "locked"
        ],
        "Financial language": [
            "payment", "bank", "invoice", "refund", "transaction",
            "billing", "credit card"
        ],
        "Link or attachment prompt": [
            "click", "link", "attachment", "download", "open",
            "follow this link"
        ],
        "Authority or impersonation language": [
            "security team", "administrator", "support team",
            "customer service", "official notice"
        ]
    }

    found = {}

    for category, keywords in indicator_categories.items():
        matches = [word for word in keywords if word in text_lower]

        if matches:
            found[category] = matches

    return found

# -----------------------------
# URL and email evidence detection
# -----------------------------
def detect_url_email_evidence(email_text):
    """
    Detects URLs and email addresses in the original email text.
    This is used as supporting evidence because the cleaning function removes
    URLs and email addresses before model prediction.
    """
    url_pattern = r"(https?://\S+|www\.\S+)"
    email_pattern = r"\b[\w\.-]+@[\w\.-]+\.\w+\b"

    urls_found = re.findall(url_pattern, email_text)
    emails_found = re.findall(email_pattern, email_text)

    return {
        "urls_found": urls_found,
        "emails_found": emails_found,
        "url_count": len(urls_found),
        "email_count": len(emails_found)
    }
# -----------------------------
# Suspicious indicator count
# -----------------------------
def count_suspicious_indicators(suspicious_indicators):
    """
    Counts how many suspicious indicator categories and matched terms were detected.
    """
    category_count = len(suspicious_indicators)

    term_count = sum(
        len(matches)
        for matches in suspicious_indicators.values()
    )

    return category_count, term_count

# -----------------------------
# Recommended action
# -----------------------------
def get_recommended_action(prediction, score, indicator_term_count, input_warning):
    """
    Provides a practical recommended action based on the prediction,
    decision score, suspicious indicator count, and input reliability.
    """
    absolute_score = abs(score)

    if input_warning or absolute_score < 0.5:
        return (
            "Manual review recommended",
            "This result is borderline or based on limited text evidence. "
            "Review the sender, links, attachments, and wider email context before deciding."
        )

    if prediction == 1:
        if indicator_term_count > 0:
            return (
                "Treat as suspicious",
                "Do not click links, open attachments, or enter personal details. "
                "Verify the message through a trusted contact method."
            )
        else:
            return (
                "Review carefully",
                "The model classified this as phishing, but few common suspicious indicators were found. "
                "Check sender identity, links, attachments, and context manually."
            )

    else:
        if indicator_term_count > 0:
            return (
                "Proceed with caution",
                "The model classified this as legitimate, but suspicious terms were detected. "
                "Check the sender and message context before interacting with links or attachments."
            )
        else:
            return (
                "Likely safe",
                "No common suspicious indicators were detected and the model classified the email as legitimate. "
                "Still check sender details and context if the message is unexpected."
            )
            
# -----------------------------
# Risk interpretation
# -----------------------------
def get_risk_level(prediction, score):
    """
    Interprets the SVM decision score as a confidence band.
    This is not a probability.
    """
    absolute_score = abs(score)

    if absolute_score < 0.5:
        confidence = "Low confidence / borderline classification"
    elif absolute_score < 1.5:
        confidence = "Moderate confidence"
    else:
        confidence = "High confidence"

    predicted_class = "Phishing" if prediction == 1 else "Legitimate"

    return f"{confidence} for {predicted_class}"
    
# -----------------------------
# Display result formatting
# -----------------------------
def get_display_result(prediction, score):
    """
    Creates a user-friendly result label that highlights borderline classifications.
    """
    absolute_score = abs(score)

    if absolute_score < 0.5:
        if prediction == 1:
            return "⚠️ Borderline phishing", "warning-card"
        else:
            return "⚠️ Borderline legitimate", "warning-card"

    if prediction == 1:
        return "🚨 Phishing", "phishing-card"
    else:
        return "✅ Legitimate", "legitimate-card"


# -----------------------------
# Short input reliability warning
# -----------------------------
def get_input_reliability_warning(cleaned_text):
    """
    Checks whether the submitted email is very short.
    Very short emails may not contain enough language evidence for reliable classification.
    """
    word_count = len(cleaned_text.split())

    if word_count < 5:
        return (
            True,
            word_count,
            "This email is very short, so the model has limited text evidence. "
            "The prediction should be treated as less reliable and reviewed manually."
        )

    if word_count < 10:
        return (
            True,
            word_count,
            "This email is fairly short, so the model may have limited context. "
            "Review the prediction alongside suspicious indicators and sender details."
        )

    return (
        False,
        word_count,
        "The email contains enough text for a more meaningful language-based analysis."
    )

# -----------------------------
# Extract influential terms
# -----------------------------
def get_influential_terms(model, vectorizer, email_features, prediction, top_n=10):
    """
    Identifies the most influential TF-IDF terms present in the submitted email.
    For Linear SVM, positive coefficients support phishing and negative coefficients
    support legitimate classification.
    """
    feature_names = vectorizer.get_feature_names_out()
    coefficients = model.coef_[0]

    non_zero_indices = email_features.nonzero()[1]

    term_data = []

    for index in non_zero_indices:
        term = feature_names[index]
        tfidf_value = email_features[0, index]
        coefficient = coefficients[index]
        contribution = tfidf_value * coefficient

        term_data.append({
            "Term": term,
            "TF-IDF Value": round(float(tfidf_value), 4),
            "Model Coefficient": round(float(coefficient), 4),
            "Contribution": round(float(contribution), 4)
        })

    terms_df = pd.DataFrame(term_data)

    if terms_df.empty:
        return terms_df

    if prediction == 1:
        terms_df = terms_df.sort_values(by="Contribution", ascending=False)
    else:
        terms_df = terms_df.sort_values(by="Contribution", ascending=True)

    return terms_df.head(top_n)

# -----------------------------
# Report export function
# -----------------------------
def create_single_prediction_report(
    email_input,
    cleaned_email,
    prediction_label,
    decision_score,
    risk_level,
    word_count,
    reliability_message,
    suspicious_indicators,
    indicator_category_count,
    indicator_term_count,
    detected_urls,
    detected_emails,
    recommended_action_title,
    recommended_action_text,
    influential_terms
):
    """
    Creates a downloadable text report for a single email prediction.
    This provides an evidence-based summary of the model output and supporting checks.
    """

    if suspicious_indicators:
        suspicious_summary = "\n".join(
            [
                f"- {category}: {', '.join(matches)}"
                for category, matches in suspicious_indicators.items()
            ]
        )
    else:
        suspicious_summary = "- None detected"

    url_summary = "\n".join([f"- {url}" for url in detected_urls]) if detected_urls else "- None detected"
    email_summary = "\n".join([f"- {email}" for email in detected_emails]) if detected_emails else "- None detected"

    if not influential_terms.empty:
        influential_summary = influential_terms.to_string(index=False)
    else:
        influential_summary = "No influential TF-IDF terms were available for this input."

    report = f"""
PHISHING EMAIL DETECTION REPORT
================================

PREDICTION SUMMARY
------------------
Prediction: {prediction_label}
Decision score: {decision_score:.4f}
Risk interpretation: {risk_level}

INPUT RELIABILITY
-----------------
Cleaned word count: {word_count}
Reliability note: {reliability_message}

SUSPICIOUS INDICATOR SUMMARY
----------------------------
Suspicious indicator categories detected: {indicator_category_count}
Suspicious indicator terms detected: {indicator_term_count}

Detected suspicious indicators:
{suspicious_summary}

URL AND EMAIL EVIDENCE
----------------------
Detected URLs:
{url_summary}

Detected email addresses:
{email_summary}

RECOMMENDED ACTION
------------------
{recommended_action_title}

{recommended_action_text}

INFLUENTIAL MODEL TERMS
-----------------------
{influential_summary}

ORIGINAL EMAIL TEXT
-------------------
{email_input}

CLEANED EMAIL TEXT USED BY MODEL
--------------------------------
{cleaned_email}

PROTOTYPE NOTE
--------------
This report was generated by a prototype phishing email detection system.
The model supports decision-making but should not replace human judgement.
Sender identity, links, attachments, and wider context should still be reviewed manually.
"""

    return report.encode("utf-8")
# -----------------------------
# Load saved model and vectorizer
# -----------------------------

def convert_df_to_csv(df):
    """
    Converts a DataFrame to CSV format for downloading.
    """
    return df.to_csv(index=False).encode("utf-8")
    
@st.cache_resource
def load_model_files():
    model_path = os.path.join("models", "linear_svm_phishing_model.pkl")
    vectorizer_path = os.path.join("models", "tfidf_vectorizer.pkl")

    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)

    return model, vectorizer


model, vectorizer = load_model_files()


# -----------------------------
# Sidebar
# -----------------------------
st.sidebar.title("About this prototype")

st.sidebar.write(
    "This application uses Natural Language Processing and a trained Linear SVM "
    "model to classify email text as legitimate or phishing."
)

st.sidebar.markdown("### Model pipeline")
st.sidebar.write("Text cleaning")
st.sidebar.write("TF-IDF feature extraction")
st.sidebar.write("Linear SVM classification")
st.sidebar.write("Keyword-based indicator analysis")

st.sidebar.markdown("### Performance summary")
st.sidebar.metric("Accuracy", "0.9867")
st.sidebar.metric("Precision", "0.9866")
st.sidebar.metric("Recall", "0.9879")
st.sidebar.metric("F1-score", "0.9872")

st.sidebar.markdown("### Limitation")
st.sidebar.write(
    "This prototype supports decision-making but should not replace human judgement."
)


# -----------------------------
# Main title
# -----------------------------
st.title("🛡️ Phishing Email Detection System")

st.write(
    "This prototype uses Natural Language Processing and Machine Learning "
    "to classify email text as either legitimate or phishing. It combines a trained "
    "Linear SVM model with simple indicator analysis to provide both a prediction "
    "and supporting explanation."
)

st.divider()


# -----------------------------
# System workflow
# -----------------------------
with st.expander("System workflow"):
    st.write(
        """
        The system follows a supervised machine learning pipeline:

        1. Raw email text is entered by the user.
        2. The text is cleaned using the same preprocessing function used during training.
        3. The cleaned text is transformed into TF-IDF features.
        4. A trained Linear SVM classifier predicts whether the email is legitimate or phishing.
        5. The app displays the prediction, decision score, suspicious indicators, and influential model terms.
        """
    )


# -----------------------------
# Sample selector
# -----------------------------
sample_type = st.selectbox(
    "Load an example email:",
    ["None", "Example phishing email", "Example legitimate email", "Example borderline email"]
)

if sample_type == "Example phishing email":
    default_email = """Dear customer, your account has been suspended due to unusual activity.
Please click the link below to verify your login details immediately:
http://fake-login.example.com
Failure to do so will result in permanent account closure."""
elif sample_type == "Example legitimate email":
    default_email = """Hi team, please find attached the meeting notes from today's project discussion.
Let me know if anything needs updating before Friday."""
elif sample_type == "Example borderline email":
    default_email = """Hello, please review the attached document when you have time.
The finance team needs confirmation before the end of the week.
If there are any issues, contact finance-team@example.com."""
else:
    default_email = ""


# -----------------------------
# User input
# -----------------------------
email_input = st.text_area(
    "Paste the email text below:",
    value=default_email,
    height=250,
    placeholder="Example: Dear customer, your account has been suspended..."
)

analyse_button = st.button("Analyse Email", type="primary")

# -----------------------------
# Prediction
# -----------------------------
if analyse_button:
    if not email_input.strip():
        st.warning("Please enter some email text before analysing.")
    else:
        cleaned_email = clean_text(email_input)
        email_features = vectorizer.transform([cleaned_email])

        prediction = model.predict(email_features)[0]
        decision_score = model.decision_function(email_features)[0]
        risk_level = get_risk_level(prediction, decision_score)

        input_warning, word_count, reliability_message = get_input_reliability_warning(cleaned_email)

        suspicious_indicators = detect_suspicious_indicators(email_input)

        indicator_category_count, indicator_term_count = count_suspicious_indicators(
            suspicious_indicators
        )

        url_email_evidence = detect_url_email_evidence(email_input)

        url_count = url_email_evidence["url_count"]
        email_address_count = url_email_evidence["email_count"]
        urls_found = url_email_evidence["urls_found"]
        emails_found = url_email_evidence["emails_found"]

        recommended_action_title, recommended_action_text = get_recommended_action(
            prediction,
            decision_score,
            indicator_term_count,
            input_warning
        )

        influential_terms = get_influential_terms(
            model,
            vectorizer,
            email_features,
            prediction
        )

        st.subheader("Prediction Result")

        result_label = "Phishing" if prediction == 1 else "Legitimate"
        display_result, result_class = get_display_result(prediction, decision_score)

        result_explanation = (
            "This email has been classified as phishing because its language patterns are closer "
            "to phishing emails seen during model training."
            if prediction == 1
            else
            "This email has been classified as legitimate because its language patterns are closer "
            "to legitimate emails seen during model training."
        )

        result_col, score_col, risk_col = st.columns(3)
        indicator_summary_col, url_email_col, action_col = st.columns(3)

        with result_col:
            st.markdown(
                f"""
                <div class="result-card {result_class}">
                    <div class="card-title">Prediction</div>
                    <div class="card-value">{display_result}</div>
                    <div class="card-text">{result_explanation}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with score_col:
            st.markdown(
                f"""
                <div class="result-card neutral-card">
                    <div class="card-title">Decision Score</div>
                    <div class="card-value">{decision_score:.4f}</div>
                    <div class="card-text">
                        Distance from the Linear SVM classification boundary.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with risk_col:
            st.markdown(
                f"""
                <div class="result-card warning-card">
                    <div class="card-title">Risk Interpretation</div>
                    <div class="card-value">{risk_level.split(" for ")[0]}</div>
                    <div class="card-text">
                        Classification confidence for: <strong>{result_label}</strong>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with indicator_summary_col:
            indicator_card_class = "warning-card" if indicator_term_count > 0 else "neutral-card"

            if indicator_term_count > 0:
                indicator_summary_text = (
                    f"Matched terms across <strong>{indicator_category_count}</strong> suspicious categories."
                )
            else:
                indicator_summary_text = (
                    "No common suspicious keyword patterns were detected."
                )

            st.markdown(
                f"""
                <div class="result-card {indicator_card_class}">
                    <div class="card-title">Suspicious Indicators</div>
                    <div class="card-value">{indicator_term_count}</div>
                    <div class="card-text">
                        {indicator_summary_text}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with url_email_col:
            if url_count > 0 or email_address_count > 0:
                evidence_card_class = "warning-card"
                evidence_text = (
                    f"Detected <strong>{url_count}</strong> URL(s) and "
                    f"<strong>{email_address_count}</strong> email address(es) in the original text."
                )
            else:
                evidence_card_class = "neutral-card"
                evidence_text = (
                    "No URLs or email addresses were detected in the original text."
                )

            st.markdown(
                f"""
                <div class="result-card {evidence_card_class}">
                    <div class="card-title">URL / Email Evidence</div>
                    <div class="card-value">{url_count + email_address_count}</div>
                    <div class="card-text">
                        {evidence_text}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with action_col:
            if recommended_action_title in ["Treat as suspicious", "Manual review recommended"]:
                action_card_class = "warning-card"
            elif recommended_action_title == "Proceed with caution":
                action_card_class = "warning-card"
            elif recommended_action_title == "Review carefully":
                action_card_class = "warning-card"
            else:
                action_card_class = "legitimate-card"

            st.markdown(
                f"""
                <div class="result-card {action_card_class}">
                    <div class="card-title">Recommended Action</div>
                    <div class="card-value">{recommended_action_title}</div>
                    <div class="card-text">
                        {recommended_action_text}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        st.caption(
            "Linear SVM does not output probability by default. "
            "The decision score represents the model's distance from the classification boundary. "
            "Larger absolute values indicate stronger confidence."
        )

        if input_warning:
            st.warning(
                f"Reliability warning: this email contains only {word_count} cleaned words. "
                f"{reliability_message}"
            )
        else:
            st.info(
                f"Input length check: this email contains {word_count} cleaned words. "
            )
        if url_count > 0 or email_address_count > 0:
            with st.expander("View URL and email evidence"):
                if urls_found:
                    st.write("#### URLs detected")
                    for url in urls_found:
                        st.code(url)

                if emails_found:
                    st.write("#### Email addresses detected")
                    for email in emails_found:
                        st.code(email)

                st.write(
                    "These items are detected from the original email text before preprocessing. "
                    "They are shown as supporting evidence because URLs and email addresses are removed "
                    "during text cleaning before TF-IDF feature extraction."
                )

        st.divider()

        explanation_col, indicator_col = st.columns(2)

        with explanation_col:
            st.write("### Classification explanation")

            if prediction == 1:
                st.write(
                    "The model placed this email on the phishing side of the decision boundary. "
                    "This means the language patterns in the email are more similar to phishing "
                    "emails than legitimate emails in the training data."
                )
            else:
                st.write(
                    "The model placed this email on the legitimate side of the decision boundary. "
                    "This means the language patterns in the email are more similar to legitimate "
                    "emails than phishing emails in the training data."
                )

            st.write(
                f"The current classification is interpreted as: **{risk_level}**."
            )

        with indicator_col:
            st.write("### Suspicious indicators")

            if suspicious_indicators:
                for category, matches in suspicious_indicators.items():
                    pills = "".join(
                        [
                            f'<span class="indicator-pill">{match}</span>'
                            for match in matches
                        ]
                    )

                    st.markdown(
                        f"""
                        <div class="result-card warning-card">
                            <div class="card-title">{category}</div>
                            <div class="card-text">{pills}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            else:
                st.markdown(
                    """
                    <div class="result-card neutral-card">
                        <div class="card-title">No common suspicious indicators detected</div>
                        <div class="card-text">
                            The rule-based indicator checker did not find common phishing keywords.
                            The machine learning model prediction should still be reviewed.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.divider()

        st.write("### Influential model terms")

        if not influential_terms.empty:
            st.write(
                "The table below shows influential TF-IDF terms from the submitted email. "
                "For the Linear SVM model, positive contributions support phishing classification, "
                "while negative contributions support legitimate classification."
            )
            st.dataframe(influential_terms, use_container_width=True)
        else:
            st.info("No influential TF-IDF terms were available for this input.")

        with st.expander("View preprocessing evidence"):
            st.write("#### Original email text")
            st.text(email_input)

            st.write("#### Cleaned text used by the model")
            st.text(cleaned_email)

            st.write("#### Feature vector shape")
            st.code(str(email_features.shape))

        st.divider()

        st.write("### Prototype note")
        st.write(
            "This system is a prototype and should support, not replace, human judgement. "
            "Suspicious emails should still be checked carefully before clicking links, "
            "opening attachments, or entering personal details."
        )
        single_report = create_single_prediction_report(
            email_input=email_input,
            cleaned_email=cleaned_email,
            prediction_label=result_label,
            decision_score=decision_score,
            risk_level=risk_level,
            word_count=word_count,
            reliability_message=reliability_message,
            suspicious_indicators=suspicious_indicators,
            indicator_category_count=indicator_category_count,
            indicator_term_count=indicator_term_count,
            detected_urls=urls_found,
            detected_emails=emails_found,
            recommended_action_title=recommended_action_title,
            recommended_action_text=recommended_action_text,
            influential_terms=influential_terms
        )

        st.download_button(
            label="Download Single Prediction Report",
            data=single_report,
            file_name="single_email_prediction_report.txt",
            mime="text/plain"
        )

# -----------------------------
# Edge Case Testing
# -----------------------------
with st.expander("Test edge cases"):
    st.write(
        """
        This section runs a small set of edge case emails through the same prediction
        pipeline. These examples test how the system responds to short, vague,
        suspicious, legitimate, and unusually formatted email content.
        """
    )

    edge_cases = [
        {
            "case_name": "Very short legitimate-style message",
            "email_text": "Can we meet tomorrow?"
        },
        {
            "case_name": "Very short suspicious message",
            "email_text": "Verify your account now."
        },
        {
            "case_name": "Legitimate message with suspicious terms",
            "email_text": (
                "Hi, please find attached the invoice for last month's project work. "
                "Let me know if the payment details need updating."
            )
        },
        {
            "case_name": "Subtle phishing-style message",
            "email_text": (
                "Hello, we noticed unusual activity on your account. "
                "Please review your details when possible."
            )
        },
        {
            "case_name": "Messy formatting and symbols",
            "email_text": (
                "URGENT!!! Your ACCOUNT has been LOCKED!!! "
                "Click here: http://fake-login.example.com ///// verify now."
            )
        },
        {
            "case_name": "Neutral workplace message",
            "email_text": (
                "Hi team, the meeting notes have been uploaded to the shared folder. "
                "Please review them before Friday."
            )
        },
        {
            "case_name": "Borderline finance-related message",
            "email_text": (
                "The finance team needs confirmation of the transaction before the end "
                "of the week."
            )
        }
    ]

    if st.button("Run Edge Case Tests"):
        edge_case_results = []

        for case in edge_cases:
            original_text = case["email_text"]
            cleaned_text = clean_text(original_text)

            features = vectorizer.transform([cleaned_text])
            prediction = model.predict(features)[0]
            score = model.decision_function(features)[0]
            risk = get_risk_level(prediction, score)
            indicators = detect_suspicious_indicators(original_text)

            prediction_label = "Phishing" if prediction == 1 else "Legitimate"

            if indicators:
                indicator_summary = "; ".join(
                    [
                        f"{category}: {', '.join(matches)}"
                        for category, matches in indicators.items()
                    ]
                )
            else:
                indicator_summary = "None detected"

            edge_case_results.append(
                {
                    "case_name": case["case_name"],
                    "email_text": original_text,
                    "cleaned_text": cleaned_text,
                    "prediction": prediction,
                    "prediction_label": prediction_label,
                    "decision_score": round(float(score), 4),
                    "risk_interpretation": risk,
                    "suspicious_indicators": indicator_summary
                }
            )

        edge_case_df = pd.DataFrame(edge_case_results)

        st.success("Edge case tests completed successfully.")

        st.write("### Edge Case Results")
        st.dataframe(edge_case_df, use_container_width=True)

        phishing_count = (
            edge_case_df["prediction_label"] == "Phishing"
        ).sum()

        legitimate_count = (
            edge_case_df["prediction_label"] == "Legitimate"
        ).sum()

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Edge cases tested", len(edge_case_df))

        with col2:
            st.metric("Predicted phishing", phishing_count)

        with col3:
            st.metric("Predicted legitimate", legitimate_count)

        edge_case_csv = convert_df_to_csv(edge_case_df)

        st.download_button(
            label="Download Edge Case Results as CSV",
            data=edge_case_csv,
            file_name="edge_case_test_results.csv",
            mime="text/csv"
        )
# -----------------------------
# Batch CSV Upload Prediction
# -----------------------------
st.divider()
st.subheader("Batch Email Analysis")

st.write(
    """
    Upload a CSV file containing multiple email texts. The system will classify each email
    as legitimate or phishing and provide a downloadable results file.
    """
)

uploaded_file = st.file_uploader(
    "Upload a CSV file for batch analysis:",
    type=["csv"]
)

if uploaded_file is not None:
    try:
        batch_df = pd.read_csv(uploaded_file)

        st.write("### Uploaded CSV Preview")
        st.dataframe(batch_df.head(), use_container_width=True)

        text_columns = batch_df.select_dtypes(include=["object"]).columns.tolist()

        if not text_columns:
            st.error("No text-based columns were found in this CSV file.")
        else:
            selected_column = st.selectbox(
                "Select the column containing email text:",
                text_columns
            )

            if st.button("Run Batch Analysis", type="primary"):
                batch_results = batch_df.copy()

                cleaned_texts = batch_results[selected_column].apply(clean_text)
                batch_features = vectorizer.transform(cleaned_texts)

                batch_predictions = model.predict(batch_features)
                batch_scores = model.decision_function(batch_features)

                batch_results["cleaned_text"] = cleaned_texts
                batch_results["prediction"] = batch_predictions
                batch_results["prediction_label"] = [
                    "Phishing" if prediction == 1 else "Legitimate"
                    for prediction in batch_predictions
                ]
                batch_results["decision_score"] = batch_scores
                batch_results["risk_interpretation"] = [
                    get_risk_level(prediction, score)
                    for prediction, score in zip(batch_predictions, batch_scores)
                ]

                st.success("Batch analysis completed successfully.")

                st.subheader("Batch Prediction Results")
                st.dataframe(batch_results, use_container_width=True)

                st.subheader("Batch Summary")

                summary_counts = batch_results["prediction_label"].value_counts()
                st.bar_chart(summary_counts)

                total_emails = len(batch_results)
                predicted_phishing = (
                    batch_results["prediction_label"] == "Phishing"
                ).sum()
                predicted_legitimate = (
                    batch_results["prediction_label"] == "Legitimate"
                ).sum()

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric("Total emails analysed", total_emails)

                with col2:
                    st.metric("Predicted phishing", predicted_phishing)

                with col3:
                    st.metric("Predicted legitimate", predicted_legitimate)

                csv_download = convert_df_to_csv(batch_results)

                st.download_button(
                    label="Download Batch Results as CSV",
                    data=csv_download,
                    file_name="phishing_batch_predictions.csv",
                    mime="text/csv"
                )

    except Exception as error:
        st.error("There was a problem processing the uploaded CSV file.")
        st.exception(error)

# -----------------------------
# Model Evidence
# -----------------------------
with st.expander("Model evaluation evidence"):
    st.write(
        """
        The model was evaluated using a held-out test set. Several machine learning
        models were compared, including Multinomial Naive Bayes, Logistic Regression,
        Linear SVM, and Random Forest. Linear SVM was selected as the final model
        because it achieved the strongest overall performance.
        """
    )

    if os.path.exists("results/confusion_matrix_linear_svm.png"):
        st.image(
            "results/confusion_matrix_linear_svm.png",
            caption="Confusion Matrix - Linear SVM"
        )
    else:
        st.warning("Confusion matrix image was not found in the results folder.")

    if os.path.exists("results/model_comparison.csv"):
        results_df = pd.read_csv("results/model_comparison.csv")
        st.dataframe(results_df, use_container_width=True)
    else:
        st.warning("Model comparison CSV was not found in the results folder.")


# -----------------------------
# Limitations and ethical use
# -----------------------------
with st.expander("Limitations and ethical use"):
    st.write(
        """
        This system is designed as a prototype for educational and analytical purposes.
        It may misclassify emails, especially if messages are very short, ambiguous,
        unusually formatted, or deliberately written to avoid common phishing language.

        The model only analyses text content. It does not verify sender identity,
        inspect attachments, scan URLs, check domain reputation, or analyse email headers.

        The model should support human decision-making rather than replace it.
        Users should still inspect sender details, links, attachments, and context before
        deciding whether an email is safe.
        """
    )


# -----------------------------
# Project Structure Note
# -----------------------------
with st.expander("How to run this application"):
    st.code("streamlit run app.py")

    st.write(
        """
        Required files:

        - app.py
        - models/linear_svm_phishing_model.pkl
        - models/tfidf_vectorizer.pkl
        - results/model_comparison.csv
        - results/confusion_matrix_linear_svm.png
        - requirements.txt
        """
    )