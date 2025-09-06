# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.home import blueprint
from flask import render_template, request, jsonify
from flask_login import login_required, current_user
from jinja2 import TemplateNotFound
import pandas as pd
import pickle
import os
from werkzeug.utils import secure_filename

from apps.config import API_GENERATOR
from apps.authentication.forms_change_password import ChangePasswordForm

@blueprint.route('/index')
@login_required
def index():
    return render_template('home/index.html', segment='index', API_GENERATOR=len(API_GENERATOR))

@blueprint.route('/profile')
@blueprint.route('/profile.html')
@login_required
def profile():
    change_password_form = ChangePasswordForm()
    return render_template('home/profile.html', 
                         segment='profile', 
                         change_password_form=change_password_form,
                         API_GENERATOR=len(API_GENERATOR))

@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment, API_GENERATOR=len(API_GENERATOR))

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


@blueprint.route('/analyze_csv', methods=['POST'])
@login_required
def analyze_csv():
    try:
        if 'csvFile' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['csvFile']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if not file.filename.lower().endswith('.csv'):
            return jsonify({'success': False, 'error': 'Please upload a CSV file'})
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        upload_path = os.path.join('uploads', filename)
        file.save(upload_path)
        
        # Read CSV file from saved location
        df = pd.read_csv(upload_path)
        
        # Access models from Flask app context
        from flask import current_app
        import numpy as np
        
        # Expected model features in correct order
        expected_features = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
            'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
            'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
            'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
            'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward'
        ]
        
        # Remove non-feature columns
        exclude_cols = ['Unnamed: 0', 'Label', 'label', 'Label_encoded', 'Attack_Type']
        for col in exclude_cols:
            if col in df.columns:
                df = df.drop(col, axis=1)
        
        # Check if we have numbered columns
        numbered_cols_available = [col for col in df.columns if col.isdigit()]
        has_numbered_cols = len(numbered_cols_available) >= 70
        
        if has_numbered_cols:
            # Sort numbered columns and take first 70
            numbered_cols_sorted = sorted([int(col) for col in numbered_cols_available])
            selected_numbered_cols = [str(i) for i in numbered_cols_sorted[:70]]
            X = df[selected_numbered_cols]
            print(f"Using numbered columns {selected_numbered_cols[0]}-{selected_numbered_cols[-1]}: {len(X.columns)} features")
        else:
            # Try to match feature names with expected features
            matched_features = []
            missing_features = []
            
            for expected_feature in expected_features:
                if expected_feature in df.columns:
                    matched_features.append(expected_feature)
                else:
                    missing_features.append(expected_feature)
                    # Add zero column for missing features
                    df[expected_feature] = 0
                    matched_features.append(expected_feature)
            
            print(f"Matched features: {len(matched_features)}")
            if missing_features:
                print(f"Missing features (filled with zeros): {len(missing_features)}")
            
            # Select only the matched features in correct order
            X = df[matched_features]
            
            # Remove any extra columns not in expected features  
            extra_cols = set(df.columns) - set(expected_features)
            if extra_cols:
                print(f"Available columns: {len(df.columns)}, Using: {len(matched_features)}, Discarding: {len(extra_cols)}")
        
        # Ensure exactly 70 features
        if len(X.columns) != 70:
            return jsonify({'success': False, 'error': f'Feature count mismatch: got {len(X.columns)}, expected 70. Available columns: {list(df.columns)[:10]}...'})
        
        print(f"Final feature set: {len(X.columns)} features ready for model")
        
        # Check if models are loaded
        if not hasattr(current_app, 'models_loaded') or not current_app.models_loaded:
            return jsonify({'success': False, 'error': 'Models not loaded'})
        
        # Get models from app context
        scaler = current_app.scaler
        model_dnn = current_app.model_dnn
        model_cnn = current_app.model_cnn
        model_group = current_app.model_group
        
        # Convert DataFrame to numpy array before scaling to avoid sklearn warnings
        print(f"Converting to numpy array: {X.shape}")
        X_array = X.values
        X_scaled = scaler.transform(X_array)
        predictions = []
        confidences = []
        
        for i in range(len(X_scaled)):
            x_sample = X_scaled[i:i+1]
            
            # Get predictions from each model
            pred_dnn = model_dnn.predict(x_sample, verbose=0)[0][0]
            pred_cnn = model_cnn.predict(x_sample.reshape(1, -1, 1), verbose=0)[0][0]
            pred_group = model_group.predict_proba(x_sample)[0][1]
            
            # Ensemble prediction
            ensemble_pred = (pred_dnn * 0.4 + pred_cnn * 0.3 + pred_group * 0.3)
            final_pred = 1 if ensemble_pred > 0.5 else 0
            
            predictions.append(final_pred)
            confidences.append(ensemble_pred)
        
        # Prepare results
        results = []
        for i, (pred, conf) in enumerate(zip(predictions, confidences)):
            result = {
                'prediction': int(pred),
                'confidence': float(conf),
                'protocol': df.iloc[i].get('Protocol', 'N/A'),
                'flow_duration': X.iloc[i].get('Flow Duration', 'N/A'),
                'total_packets': (X.iloc[i].get('Total Fwd Packets', 0) + X.iloc[i].get('Total Backward Packets', 0)) if 'Total Fwd Packets' in X.columns else 'N/A'
            }
            results.append(result)
        
        # Calculate statistics
        total_records = len(predictions)
        attacks_detected = sum(predictions)
        benign_traffic = total_records - attacks_detected
        
        stats = {
            'total': total_records,
            'threats': attacks_detected,
            'normal': benign_traffic
        }
        
        # Prepare file content for preview (first 10 rows)
        file_content = df.head(10).to_dict('records')
        
        return jsonify({
            'success': True,
            'results': results,
            'stats': stats,
            'file_content': file_content
        })
        
    except Exception as e:
        print(f"Error in analyze_csv: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
