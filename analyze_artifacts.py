import os
import re
import datetime
import json
import pandas as pd
from collections import Counter
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

def analyze_logs(logs_directory):
    # Regular expression pattern to extract relevant information from logs
    # Customize this pattern based on the log format and the information you want to extract
    log_pattern = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(?P<message>.*)"

    # Dictionary to store analyzed data
    analyzed_data = {}

    for filename in os.listdir(logs_directory):
        if filename.endswith(".log"):
            file_path = os.path.join(logs_directory, filename)
            with open(file_path, "r") as file:
                for line in file:
                    match = re.search(log_pattern, line)
                    if match:
                        timestamp_str = match.group("timestamp")
                        message = match.group("message")

                        # Convert timestamp string to datetime object
                        try:
                            timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            # Handle invalid timestamp formats if necessary
                            continue

                        # Store analyzed data in the dictionary
                        if timestamp in analyzed_data:
                            analyzed_data[timestamp].append(message)
                        else:
                            analyzed_data[timestamp] = [message]

    return analyzed_data

def perform_advanced_analysis(analyzed_data):
    # Perform advanced analysis on the extracted data
    # For example, identifying patterns, anomalies, or aggregating data.

    # Concatenate all log messages for text analysis
    all_logs = [message for messages in analyzed_data.values() for message in messages]

    # Tokenize and remove stop words for text analysis
    stop_words = set(stopwords.words("english"))
    tokenized_logs = [word_tokenize(message.lower()) for message in all_logs]
    filtered_logs = [[word for word in tokens if word.isalnum() and word not in stop_words] for tokens in tokenized_logs]

    # Convert filtered logs into a Pandas DataFrame for further analysis
    log_df = pd.DataFrame({"Log": [" ".join(tokens) for tokens in filtered_logs]})

    # Perform text analysis using TF-IDF and K-Means clustering
    tfidf_vectorizer = TfidfVectorizer()
    tfidf_matrix = tfidf_vectorizer.fit_transform(log_df["Log"])
    num_clusters = 5  # You can adjust the number of clusters based on your needs
    kmeans = KMeans(n_clusters=num_clusters, random_state=42)
    log_df["Cluster"] = kmeans.fit_predict(tfidf_matrix)

    # Get the most frequent words in each cluster
    cluster_words = {}
    for cluster_id in range(num_clusters):
        cluster_logs = log_df[log_df["Cluster"] == cluster_id]["Log"]
        word_freq = Counter(" ".join(cluster_logs).split())
        cluster_words[cluster_id] = word_freq.most_common(10)

    # Convert the analyzed data to a JSON object for easy export
    analysis_result = {
        "Log_Clusters": log_df.to_dict(orient="records"),
        "Cluster_Words": cluster_words
    }

    return analysis_result

def main():
    # Replace this variable with the path to your logs directory
    logs_directory = "logs"

    analyzed_data = analyze_logs(logs_directory)

    # Perform advanced analysis on the extracted data
    analysis_result = perform_advanced_analysis(analyzed_data)

    # Save the analysis result to a JSON file
    with open("analysis_result.json", "w") as json_file:
        json.dump(analysis_result, json_file, indent=4)

if __name__ == "__main__":
    main()
