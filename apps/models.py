from apps import db
from datetime import datetime


# Book Sample
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64))

# CICIDS2017 Analysis Results
class AnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    total_records = db.Column(db.Integer, nullable=False)
    attacks_detected = db.Column(db.Integer, nullable=False)
    benign_traffic = db.Column(db.Integer, nullable=False)
    analysis_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True)
    
    def __repr__(self):
        return f'<AnalysisResult {self.filename}: {self.attacks_detected}/{self.total_records} attacks>'

# Individual Attack Detection Records
class DetectionRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis_result.id'), nullable=False)
    record_index = db.Column(db.Integer, nullable=False)
    prediction = db.Column(db.Integer, nullable=False)  # 0 = benign, 1 = attack
    confidence = db.Column(db.Float, nullable=False)
    protocol = db.Column(db.String(50))
    flow_duration = db.Column(db.Float)
    total_packets = db.Column(db.Integer)
    
    analysis = db.relationship('AnalysisResult', backref=db.backref('records', lazy=True))
    
    def __repr__(self):
        return f'<DetectionRecord {self.id}: {"ATTACK" if self.prediction else "BENIGN"}>'