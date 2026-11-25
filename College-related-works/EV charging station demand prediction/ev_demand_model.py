import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error
import matplotlib.pyplot as plt
import os
from datetime import datetime, timedelta

try:
    from acnportal import acndata
except ImportError:
    print("acnportal not installed. Run: pip install acnportal")

# Configuration
API_TOKEN = "DEMO_TOKEN" # Replace with your ACN-Data API token from https://ev.caltech.edu/dataset
SITE = 'caltech'
DATA_FILE = 'acn_data_sample.csv'

def generate_dummy_data():
    """Generates a dummy dataset in case the ACN API is inaccessible without a valid token."""
    print("Generating dummy data for demonstration purposes...")
    np.random.seed(42)
    start_time = datetime(2023, 1, 1)
    
    sessions = []
    for i in range(2000):
        # Random connection time within a 3-month period
        conn_time = start_time + timedelta(hours=np.random.randint(0, 24 * 90))
        # Disconnection time is 1 to 8 hours later
        disconn_time = conn_time + timedelta(hours=np.random.randint(1, 9))
        # Random energy delivered (between 5 and 50 kWh)
        kwh = np.random.uniform(5, 50)
        
        sessions.append({
            'connectionTime': conn_time.strftime("%a, %d %b %Y %H:%M:%S GMT"),
            'disconnectionTime': disconn_time.strftime("%a, %d %b %Y %H:%M:%S GMT"),
            'kWhDelivered': kwh
        })
        
    df = pd.DataFrame(sessions)
    df.to_csv(DATA_FILE, index=False)
    print(f"Dummy data saved to {DATA_FILE}")
    return df

def fetch_and_save_data():
    """Fetches a sample of data from ACN-Data and saves it to a CSV."""
    if API_TOKEN == "DEMO_TOKEN":
        print("Using DEMO_TOKEN. Attempting to fetch data, but it may fail without a real token.")
        
    print("Fetching data from ACN API...")
    try:
        client = acndata.DataClient(API_TOKEN)
        # We will try to fetch the first 2000 sessions to keep it light
        sessions = client.get_sessions(SITE)
        
        session_list = []
        for session in sessions:
            session_list.append(session)
            if len(session_list) >= 2000:
                break
                
        df = pd.DataFrame(session_list)
        df.to_csv(DATA_FILE, index=False)
        print(f"Real ACN data saved to {DATA_FILE}")
        return df
    except Exception as e:
        print(f"\nError fetching real data: {e}")
        print("Please ensure your API token is correct. You can register at https://ev.caltech.edu/dataset")
        print("Falling back to dummy data generation so you can see the model in action...\n")
        return generate_dummy_data()

def load_and_preprocess_data(df):
    """Preprocesses the raw session data into hourly demand."""
    print("Preprocessing data...")
    # Convert string times to datetime objects
    # ACN data dates are usually in RFC 1123 format or similar
    df['connectionTime'] = pd.to_datetime(df['connectionTime'], format='mixed', utc=True)
    
    # We want to predict total energy demand (kWh) per hour.
    # To keep it simple, we'll assign the total energy of a session to its connection hour.
    df.set_index('connectionTime', inplace=True)
    
    # Resample to hourly data, summing the 'kWhDelivered'
    # 'h' is used for hourly frequency in pandas 2.2.0+
    hourly_demand = df['kWhDelivered'].resample('h').sum().reset_index()
    hourly_demand.rename(columns={'kWhDelivered': 'Total_Demand_kWh', 'connectionTime': 'Time'}, inplace=True)
    
    # Fill missing hours with 0 demand
    hourly_demand['Total_Demand_kWh'] = hourly_demand['Total_Demand_kWh'].fillna(0)
    
    return hourly_demand

def engineer_features(df):
    """Creates time-based and lag features for the model."""
    print("Engineering features...")
    df['Hour'] = df['Time'].dt.hour
    df['DayOfWeek'] = df['Time'].dt.dayofweek
    df['IsWeekend'] = df['DayOfWeek'].apply(lambda x: 1 if x >= 5 else 0)
    
    # Lag feature: Demand from the previous hour
    df['Lag_1_Hour'] = df['Total_Demand_kWh'].shift(1)
    
    # Drop the first row which now has a NaN value due to the lag shift
    df.dropna(inplace=True)
    return df

def train_and_evaluate_model(df):
    """Trains a Random Forest model and evaluates it."""
    print("Training model...")
    # Features (X) and Target (y)
    X = df[['Hour', 'DayOfWeek', 'IsWeekend', 'Lag_1_Hour']]
    y = df['Total_Demand_kWh']
    
    # Split chronologically (80% train, 20% test)
    split_idx = int(len(df) * 0.8)
    X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
    y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]
    
    # Train Random Forest
    model = RandomForestRegressor(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Predict
    predictions = model.predict(X_test)
    
    # Evaluate
    mae = mean_absolute_error(y_test, predictions)
    rmse = np.sqrt(mean_squared_error(y_test, predictions))
    print(f"\n--- Model Evaluation ---")
    print(f"Mean Absolute Error (MAE): {mae:.2f} kWh")
    print(f"Root Mean Squared Error (RMSE): {rmse:.2f} kWh")
    
    # Plot results
    print("Generating plot...")
    plt.figure(figsize=(12, 6))
    plt.plot(df['Time'].iloc[split_idx:].values, y_test.values, label='Actual Demand', alpha=0.7)
    plt.plot(df['Time'].iloc[split_idx:].values, predictions, label='Predicted Demand', alpha=0.7)
    plt.xlabel('Time')
    plt.ylabel('Demand (kWh)')
    plt.title('EV Charging Demand: Actual vs Predicted')
    plt.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()
    plot_file = 'demand_prediction_plot.png'
    plt.savefig(plot_file)
    print(f"Plot saved to {plot_file}")

def main():
    print("Starting EV Demand Prediction Pipeline...")
    if not os.path.exists(DATA_FILE):
        df = fetch_and_save_data()
    else:
        print(f"Loading existing data from {DATA_FILE}...")
        df = pd.read_csv(DATA_FILE)
        
    hourly_df = load_and_preprocess_data(df)
    featured_df = engineer_features(hourly_df)
    train_and_evaluate_model(featured_df)
    print("Pipeline finished successfully!")

if __name__ == "__main__":
    main()
