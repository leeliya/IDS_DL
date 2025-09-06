import os
from flask import Flask, request, jsonify, render_template
import pickle
import pandas as pd
import joblib
import tensorflow as tf
import numpy as np
from flask_migrate import Migrate
from flask_minify import Minify
from sys import exit

# from api_generator.commands import gen_api  # Désactivé pour éviter les erreurs
from apps.config import config_dict
from apps import create_app, db

# Configuration de l'application
DEBUG = (os.getenv('DEBUG', 'False') == 'True')
get_config_mode = 'Debug' if DEBUG else 'Production'

try:
    app_config = config_dict[get_config_mode.capitalize()]
except KeyError:
    exit('Error: Invalid <config_mode>. Expected values [Debug, Production]')

# Création de l'application Flask
app = create_app(app_config)

# Charger tous les modèles de l'ensemble
models_loaded = False
scaler = model_dnn = model_cnn = model_group = model_web = model_non_web = iso_forest = None

try:
    scaler = joblib.load('scaler.pkl')
    model_dnn = tf.keras.models.load_model('ids_dnn_model.h5')
    model_cnn = tf.keras.models.load_model('ids_cnn_model.h5')
    model_group = joblib.load('ids_lightgbm_model_group.pkl')
    model_web = joblib.load('ids_lightgbm_model_web.pkl')
    model_non_web = joblib.load('ids_lightgbm_model_non_web.pkl')
    iso_forest = joblib.load('ids_isolation_forest.pkl')
    models_loaded = True
    print("Tous les modèles chargés avec succès")
    
    # Store models in app context
    app.models_loaded = True
    app.scaler = scaler
    app.model_dnn = model_dnn
    app.model_cnn = model_cnn
    app.model_group = model_group
    app.model_web = model_web
    app.model_non_web = model_non_web
    app.iso_forest = iso_forest
except Exception as e:
    print(f"Erreur lors du chargement des modèles: {e}")
    models_loaded = False
    app.models_loaded = False
  

# @app.route('/')
# def home():
#     return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Récupérer les données du formulaire
        data = request.form.to_dict()
        data_to_predict = [float(data[feature]) for feature in data.keys()]

        # Liste des noms de caractéristiques utilisés lors de l'entraînement du modèle
        feature_names = [
            'Unnamed: 0', 'Source Port', 'Destination Port', 'Protocol', 'Flow Duration', 'Total Fwd Packets',
            'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
            'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Bwd IAT Max', 'Bwd IAT Min', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
            'Packet Length Variance', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean',
            'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]

        # Convertir les données en DataFrame pandas
        data_to_predict_df = pd.DataFrame([data_to_predict], columns=feature_names)

        # Faire une prédiction avec l'ensemble
        if not models_loaded:
            return jsonify({'error': 'Modèles non disponibles'}), 500
            
        # Préprocessing
        X_scaled = scaler.transform(data_to_predict_df)
        
        # Prédictions de chaque modèle
        pred_dnn = model_dnn.predict(X_scaled, verbose=0)[0][0]
        pred_cnn = model_cnn.predict(X_scaled.reshape(1, -1, 1), verbose=0)[0][0]
        pred_group = model_group.predict_proba(X_scaled)[0][1]
        
        # Ensemble final (moyenne pondérée)
        ensemble_pred = (pred_dnn * 0.4 + pred_cnn * 0.3 + pred_group * 0.3)
        final_prediction = 1 if ensemble_pred > 0.5 else 0
        
        return jsonify({
            'prediction': final_prediction,
            'confidence': float(ensemble_pred),
            'individual_scores': {
                'dnn': float(pred_dnn),
                'cnn': float(pred_cnn), 
                'lightgbm': float(pred_group)
            }
        })
    except Exception as e:
        # Renvoyer une erreur en cas d'exception
        return jsonify({'error': str(e)}), 500

# Initialiser Flask-Migrate
Migrate(app, db)

# Minifier l'application si elle n'est pas en mode debug
if not DEBUG:
    Minify(app=app, html=True, js=False, cssless=False)

# Log des informations de configuration
if DEBUG:
    app.logger.info('DEBUG            = ' + str(DEBUG))
    app.logger.info('Page Compression = ' + ('FALSE' if DEBUG else 'TRUE'))
    app.logger.info('DBMS             = ' + app_config.SQLALCHEMY_DATABASE_URI)
    app.logger.info('ASSETS_ROOT      = ' + app_config.ASSETS_ROOT)

# Ajouter les commandes CLI (désactivé)
# for command in [gen_api, ]:
#     app.cli.add_command(command)

if __name__ == "__main__":
    app.run(debug=DEBUG)