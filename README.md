\# Phishing Email Detection System



A Streamlit-based phishing email detection prototype that uses Natural Language Processing and Machine Learning to classify email text as either \*\*phishing\*\* or \*\*legitimate\*\*.



The system uses a trained \*\*Linear Support Vector Machine (Linear SVM)\*\* model with \*\*TF-IDF feature extraction\*\*. It also includes rule-based supporting evidence such as suspicious keyword indicators, URL/email detection, input reliability warnings, recommended actions, edge case testing, batch CSV analysis, and downloadable prediction reports.



---



\## Dataset Note



The full dataset files used during development are included in the submitted project zip under the `data/` folder.



However, the large CSV dataset files are not included in the GitHub repository because they exceed GitHub's standard file size limit.



The GitHub repository still contains the trained model files, application code, notebook, results, requirements file, README, and sample batch input file needed to review and run the application.



---



\## Project Overview



Phishing emails are a common cybersecurity threat that attempt to trick users into revealing sensitive information, clicking malicious links, opening unsafe attachments, or trusting impersonated senders.



This project aims to support phishing email analysis by combining:



\- Machine learning classification

\- Text pre-processing

\- TF-IDF feature extraction

\- Suspicious indicator detection

\- URL and email evidence extraction

\- Input reliability checks

\- Recommended user actions

\- Batch email analysis

\- Exportable prediction reports



The application is designed as an educational prototype and should support, not replace, human judgement.



---



\## Features



\### Email Classification



Users can paste an email into the application and receive a prediction of either:



\- \*\*Phishing\*\*

\- \*\*Legitimate\*\*



The prediction is generated using a trained Linear SVM model.



---



\### Decision Score and Risk Interpretation



The system displays the Linear SVM decision score, which represents the model's distance from the classification boundary.



The app interprets this score as:



\- Low confidence / borderline classification

\- Moderate confidence

\- High confidence



This helps users understand how strong the model's classification is.



---



\### Short Input Reliability Warning



Very short emails may not provide enough language evidence for reliable classification.



The system checks the cleaned word count and warns the user if the email is too short or has limited context.



---



\### Suspicious Indicator Detection



The app checks the original email text for common phishing-related language patterns, including:



\- Urgency language

\- Account or login requests

\- Threats or consequences

\- Financial language

\- Link or attachment prompts

\- Authority or impersonation language



The system also counts how many suspicious indicator categories and matched terms were detected.



---



\### URL and Email Evidence Detection



The system detects URLs and email addresses from the original email text before preprocessing.



This is included because URLs and email addresses are removed during text cleaning before TF-IDF feature extraction.



The app displays:



\- Number of URLs detected

\- Number of email addresses detected

\- Extracted URLs and email addresses in an expandable evidence section



---



\### Recommended Action



The app provides a practical recommendation based on:



\- Model prediction

\- Decision score

\- Suspicious indicator count

\- Input reliability warning



Possible recommendations include:



\- Treat as suspicious

\- Manual review recommended

\- Proceed with caution

\- Review carefully

\- Likely safe



---



\### Influential Model Terms



The system displays influential TF-IDF terms found in the submitted email.



For the Linear SVM model:



\- Positive contributions support phishing classification

\- Negative contributions support legitimate classification



This helps explain which terms contributed most to the model's decision.



---



\### Export Single Prediction Report



Users can download a text report for a single email prediction.



The report includes:



\- Prediction result

\- Decision score

\- Risk interpretation

\- Input reliability information

\- Suspicious indicator summary

\- URL and email evidence

\- Recommended action

\- Influential model terms

\- Original email text

\- Cleaned email text



---



\### Edge Case Testing



The app includes built-in edge case tests to evaluate how the system responds to different email types, including:



\- Very short legitimate-style messages

\- Very short suspicious messages

\- Legitimate messages containing suspicious terms

\- Subtle phishing-style messages

\- Messy formatting and symbols

\- Neutral workplace messages

\- Borderline finance-related messages



The edge case results can be downloaded as a CSV file.



---



\### Batch CSV Upload Analysis



Users can upload a CSV file containing multiple email texts.



The system allows the user to select the email text column, then generates predictions for each row.



The batch output includes:



\- Cleaned text

\- Prediction

\- Prediction label

\- Decision score

\- Risk interpretation



The batch results can be downloaded as a CSV file.



---



\## Technologies Used



\- Python

\- Streamlit

\- Pandas

\- Scikit-learn

\- Joblib

\- Regular Expressions

\- TF-IDF Vectorization

\- Linear Support Vector Machine



---



\## Machine Learning Pipeline



The system follows this pipeline:



1\. Raw email text is entered by the user.

2\. Text is cleaned using the same preprocessing method used during model training.

3\. Cleaned text is transformed into TF-IDF features.

4\. A trained Linear SVM model classifies the email.

5\. Supporting evidence is generated using rule-based checks.

6\. The app displays the prediction, risk interpretation, indicators, evidence, influential terms, and recommended action.



---



\## Text Preprocessing



The cleaning function performs the following steps:



\- Converts text to lowercase

\- Removes URLs

\- Removes email addresses

\- Removes numbers

\- Removes punctuation and special characters

\- Removes extra whitespace



This ensures the input text is processed consistently with the training pipeline.



---



\## Model Performance



The final selected model was Linear SVM.



Performance summary:



| Metric | Score |

|---|---:|

| Accuracy | 0.9867 |

| Precision | 0.9866 |

| Recall | 0.9879 |

| F1-score | 0.9872 |



Linear SVM was selected because it achieved the strongest overall performance compared with the other tested models.



---



\## Project Structure



```text

PhishingDetectionSystem/

│

├── app.py

├── README.md

├── requirements.txt

│

├── models/

│   ├── linear\\\_svm\\\_phishing\\\_model.pkl

│   └── tfidf\\\_vectorizer.pkl

│

├── results/

│   ├── confusion\\\_matrix\\\_linear\\\_svm.png

│   └── model\\\_comparison.csv

│

├── data/

│   └── phishing\\\_email.csv

│

├── notebooks/

│   └── phishing\\\_email\\\_detection\\\_training.ipynb

│

└── sample\\\_inputs/

\&nbsp;   └── sample\\\_batch\\\_emails.csv

```



---



\## Required Files



The application requires the following files:



```text

app.py

models/linear\\\_svm\\\_phishing\\\_model.pkl

models/tfidf\\\_vectorizer.pkl

results/model\\\_comparison.csv

results/confusion\\\_matrix\\\_linear\\\_svm.png

requirements.txt

```



If the model or vectorizer files are missing, the application will not be able to run predictions.



---



\## Installation



Clone the repository:



```bash

git clone https://github.com/Raeken337/phishing-email-detection-system.git

cd phishing-email-detection-system

```



Install the required dependencies:



```bash

pip install -r requirements.txt

```



\## Running the Application



Run the Streamlit app using:



```bash

streamlit run app.py

```



The application will open in your browser.



---



\## Example Inputs



Example Phishing Emails:

\- Dear customer, your account has been suspended due to unusual activity.

\- Please click the link below to verify your login details immediately:

\- http://fake-login.example.com

\- Failure to do so will result in permanent account closure.



Example Legitimate Email:



\- Hi team, please find attached the meeting notes from today's project discussion.

\- Let me know if anything needs updating before Friday.



Example Borderline Email:

\- Hello, please review the attached document when you have time.

\- The finance team needs confirmation before the end of the week.

\- If there are any issues, contact finance-team@example.com.



---



\## Batch CSV Format



For batch analysis, upload a CSV file containing at least one text-based column.



Example:



email\_text

"Dear customer, your account has been suspended. Click the link to verify your details."

"Hi team, the meeting notes have been uploaded to the shared folder."



The app will allow the user to select the column containing email text.



---



\## Limitations



This system is a prototype and has several limitations:



\- It only analyses email text content.

\- It does not verify sender identity.

\- It does not inspect email headers.

\- It does not scan attachments.

\- It does not check live URL reputation.

\- It does not detect spoofed domains.

\- It may misclassify very short, vague, unusual, or deliberately evasive emails.

\- Suspicious keyword detection is rule-based and may produce false positives.



The system should be used as a decision-support tool rather than a final authority.



---



\## Ethical Use



This project is intended for educational and defensive cybersecurity purposes.



It should be used to understand how phishing detection systems can support email analysis and user awareness.



Users should still manually review suspicious messages, especially before clicking links, opening attachments, or entering sensitive information.



---



\## Future Improvements



Possible future improvements include:



\- Email header analysis

\- Sender domain verification

\- URL reputation checking

\- Attachment scanning

\- Probability calibration for model confidence

\- Larger and more diverse training datasets

\- Improved phishing pattern detection

\- Integration with email inbox systems

\- More advanced explainability features



---



\## Author



Created as part of a phishing email detection system project using Python, Streamlit, Natural Language Processing, and Machine Learning.





```md

git clone https://github.com/Raeken337/phishing-email-detection-system.git


