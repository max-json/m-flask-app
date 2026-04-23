import joblib
from url_feature_extraction import extract_features

print("Loading model...")
model = joblib.load('phishing_model.pkl')
scaler = joblib.load('scaler.pkl')

url = "http://paypal.com.verify-account.xyz/login"
print(f"Testing URL: {url}")

features = extract_features(url)
print(f"Number of features: {len(features)}")

features_scaled = scaler.transform([features])
pred = model.predict(features_scaled)[0]
prob = model.predict_proba(features_scaled)[0]

print(f"Prediction: {pred} (1=Phishing, 0=Safe)")
print(f"Probability: {prob}")

