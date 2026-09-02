"""
Synthetic Clinical Dataset Generator for CPDPM

This module generates realistic but anonymized healthcare data for
testing and demonstrating CPDPM cryptographic capabilities without
using actual patient information.

Author: CPDPM Research Team
"""

import random
import datetime
from typing import Dict, List, Tuple, Optional
import json
import pandas as pd
import numpy as np
from dataclasses import dataclass, asdict
import uuid


@dataclass
class PatientRecord:
    """Represents a synthetic patient record."""
    patient_id: str
    age: int
    gender: str
    height_cm: float
    weight_kg: float
    blood_type: str
    allergies: List[str]
    chronic_conditions: List[str]
    emergency_contact: str
    insurance_id: str
    created_date: str


@dataclass
class VitalSigns:
    """Represents vital signs measurement."""
    patient_id: str
    timestamp: str
    heart_rate_bpm: int
    blood_pressure_systolic: int
    blood_pressure_diastolic: int
    temperature_celsius: float
    oxygen_saturation: float
    respiratory_rate: int
    measurement_id: str


@dataclass
class LabResult:
    """Represents laboratory test results."""
    patient_id: str
    test_date: str
    test_type: str
    test_name: str
    result_value: float
    unit: str
    reference_range: str
    abnormal_flag: bool
    lab_id: str


@dataclass
class MedicalNote:
    """Represents clinical notes."""
    patient_id: str
    note_date: str
    note_type: str
    provider: str
    subject: str
    content: str
    note_id: str


class SyntheticHealthcareGenerator:
    """
    Generator for synthetic healthcare data that mimics real clinical datasets
    while maintaining complete anonymity and HIPAA compliance.
    """
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize the synthetic data generator.
        
        Args:
            seed: Random seed for reproducible generation
        """
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
        
        # Medical reference data
        self.blood_types = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
        self.genders = ['Male', 'Female', 'Other']
        
        self.common_allergies = [
            'Penicillin', 'Shellfish', 'Peanuts', 'Tree nuts', 'Latex',
            'Sulfa drugs', 'Eggs', 'Soy', 'Milk', 'Wheat', 'None known'
        ]
        
        self.chronic_conditions = [
            'Hypertension', 'Diabetes Type 2', 'Diabetes Type 1', 'Asthma',
            'COPD', 'Arthritis', 'Heart disease', 'Depression', 'Anxiety',
            'High cholesterol', 'Thyroid disorder', 'None'
        ]
        
        self.lab_tests = {
            'CBC': {
                'WBC': (4.0, 11.0, '10^3/uL'),
                'RBC': (4.2, 5.9, '10^6/uL'),
                'Hemoglobin': (12.0, 17.0, 'g/dL'),
                'Hematocrit': (36.0, 50.0, '%'),
                'Platelets': (150, 450, '10^3/uL')
            },
            'Basic Metabolic Panel': {
                'Glucose': (70, 100, 'mg/dL'),
                'Sodium': (136, 145, 'mmol/L'),
                'Potassium': (3.5, 5.1, 'mmol/L'),
                'Chloride': (98, 107, 'mmol/L'),
                'BUN': (7, 20, 'mg/dL'),
                'Creatinine': (0.6, 1.2, 'mg/dL')
            },
            'Lipid Panel': {
                'Total Cholesterol': (100, 200, 'mg/dL'),
                'HDL': (40, 100, 'mg/dL'),
                'LDL': (70, 130, 'mg/dL'),
                'Triglycerides': (50, 150, 'mg/dL')
            },
            'Liver Function': {
                'ALT': (7, 40, 'U/L'),
                'AST': (10, 40, 'U/L'),
                'Bilirubin Total': (0.3, 1.2, 'mg/dL'),
                'Alkaline Phosphatase': (44, 147, 'U/L')
            }
        }
        
        self.note_types = [
            'Progress Note', 'Admission Note', 'Discharge Summary',
            'Consultation Note', 'Procedure Note', 'History and Physical'
        ]
        
        self.providers = [
            'Dr. Smith', 'Dr. Johnson', 'Dr. Williams', 'Dr. Brown',
            'Dr. Jones', 'Dr. Garcia', 'Dr. Miller', 'Dr. Davis',
            'Dr. Rodriguez', 'Dr. Martinez', 'Nurse Thompson', 'Nurse Wilson'
        ]
    
    def generate_patient_id(self) -> str:
        """Generate a unique patient identifier."""
        return f"PAT-{uuid.uuid4().hex[:8].upper()}"
    
    def generate_patient_record(self) -> PatientRecord:
        """Generate a synthetic patient record."""
        patient_id = self.generate_patient_id()
        age = random.randint(18, 90)
        gender = random.choice(self.genders)
        
        # Generate realistic height/weight based on age and gender
        if gender == 'Male':
            height = random.normalvariate(175, 7)  # cm
            bmi = random.normalvariate(26, 4)
        else:
            height = random.normalvariate(162, 6)  # cm
            bmi = random.normalvariate(25, 4)
        
        weight = bmi * (height / 100) ** 2
        
        # Ensure realistic ranges
        height = max(150, min(210, height))
        weight = max(40, min(150, weight))
        
        # Generate medical history
        num_allergies = random.choices([0, 1, 2, 3], weights=[30, 50, 15, 5])[0]
        allergies = random.sample(self.common_allergies, num_allergies) if num_allergies > 0 else ["None known"]
        
        num_conditions = random.choices([0, 1, 2, 3], weights=[40, 35, 20, 5])[0]
        conditions = random.sample(self.chronic_conditions[:-1], num_conditions) if num_conditions > 0 else ["None"]
        
        return PatientRecord(
            patient_id=patient_id,
            age=age,
            gender=gender,
            height_cm=round(height, 1),
            weight_kg=round(weight, 1),
            blood_type=random.choice(self.blood_types),
            allergies=allergies,
            chronic_conditions=conditions,
            emergency_contact=f"Contact-{random.randint(100000, 999999)}",
            insurance_id=f"INS-{random.randint(100000000, 999999999)}",
            created_date=self._random_date().isoformat()
        )
    
    def generate_vital_signs(self, patient_id: str, num_readings: int = 1) -> List[VitalSigns]:
        """Generate synthetic vital signs for a patient."""
        vitals = []
        base_date = datetime.datetime.now() - datetime.timedelta(days=30)
        
        for i in range(num_readings):
            timestamp = base_date + datetime.timedelta(
                hours=random.randint(0, 720),  # Within 30 days
                minutes=random.randint(0, 59)
            )
            
            # Generate realistic vital signs with some correlation
            age_factor = random.uniform(0.8, 1.2)
            
            heart_rate = int(random.normalvariate(75, 12) * age_factor)
            heart_rate = max(50, min(150, heart_rate))
            
            # Blood pressure correlated with age and heart rate
            systolic = int(random.normalvariate(120, 15) * age_factor)
            systolic = max(90, min(180, systolic))
            diastolic = int(systolic * random.uniform(0.6, 0.8))
            
            temperature = round(random.normalvariate(36.8, 0.4), 1)
            temperature = max(35.0, min(40.0, temperature))
            
            oxygen_sat = round(random.normalvariate(98, 1.5), 1)
            oxygen_sat = max(85.0, min(100.0, oxygen_sat))
            
            respiratory_rate = int(random.normalvariate(16, 3))
            respiratory_rate = max(10, min(30, respiratory_rate))
            
            vitals.append(VitalSigns(
                patient_id=patient_id,
                timestamp=timestamp.isoformat(),
                heart_rate_bpm=heart_rate,
                blood_pressure_systolic=systolic,
                blood_pressure_diastolic=diastolic,
                temperature_celsius=temperature,
                oxygen_saturation=oxygen_sat,
                respiratory_rate=respiratory_rate,
                measurement_id=f"VS-{uuid.uuid4().hex[:8].upper()}"
            ))
        
        return vitals
    
    def generate_lab_results(self, patient_id: str, num_tests: int = 5) -> List[LabResult]:
        """Generate synthetic laboratory results for a patient."""
        results = []
        test_date = self._random_date()
        
        # Select random test panels
        selected_panels = random.sample(list(self.lab_tests.keys()), min(num_tests, len(self.lab_tests)))
        
        for panel in selected_panels:
            for test_name, (low, high, unit) in self.lab_tests[panel].items():
                # Generate result with some chance of abnormal values
                if random.random() < 0.85:  # 85% normal results
                    result = random.uniform(low, high)
                    abnormal = False
                else:  # 15% abnormal results
                    if random.random() < 0.5:
                        result = random.uniform(low * 0.5, low * 0.9)  # Below normal
                    else:
                        result = random.uniform(high * 1.1, high * 1.5)  # Above normal
                    abnormal = True
                
                reference_range = f"{low}-{high}"
                
                results.append(LabResult(
                    patient_id=patient_id,
                    test_date=test_date.isoformat(),
                    test_type=panel,
                    test_name=test_name,
                    result_value=round(result, 2),
                    unit=unit,
                    reference_range=reference_range,
                    abnormal_flag=abnormal,
                    lab_id=f"LAB-{uuid.uuid4().hex[:8].upper()}"
                ))
        
        return results
    
    def generate_medical_note(self, patient_id: str) -> MedicalNote:
        """Generate a synthetic medical note."""
        note_type = random.choice(self.note_types)
        provider = random.choice(self.providers)
        note_date = self._random_date()
        
        # Generate realistic note content based on type
        subjects = {
            'Progress Note': ['Routine follow-up', 'Medication review', 'Symptom assessment'],
            'Admission Note': ['Emergency admission', 'Planned procedure', 'Observation'],
            'Discharge Summary': ['Successful treatment', 'Home care instructions', 'Follow-up plan'],
            'Consultation Note': ['Specialist consultation', 'Second opinion', 'Referral evaluation'],
            'Procedure Note': ['Minor procedure', 'Diagnostic test', 'Treatment administration'],
            'History and Physical': ['Annual exam', 'Pre-operative assessment', 'Comprehensive evaluation']
        }
        
        subject = random.choice(subjects.get(note_type, ['General note']))
        
        # Generate realistic note content
        content_templates = [
            f"Patient presents for {subject.lower()}. Review of systems is negative except as noted. Physical examination reveals stable condition. Plan: continue current medications and follow up as scheduled.",
            f"Assessment: {subject}. Patient reports feeling well overall. Vital signs stable. Laboratory results reviewed and discussed with patient. Recommendations provided for ongoing care.",
            f"Clinical impression: {subject}. Patient education provided regarding condition management. Prescription updated as needed. Return visit scheduled.",
            f"Encounter for {subject.lower()}. No acute distress noted. Treatment plan reviewed and modified as appropriate. Patient demonstrates understanding of instructions."
        ]
        
        content = random.choice(content_templates)
        
        return MedicalNote(
            patient_id=patient_id,
            note_date=note_date.isoformat(),
            note_type=note_type,
            provider=provider,
            subject=subject,
            content=content,
            note_id=f"NOTE-{uuid.uuid4().hex[:8].upper()}"
        )
    
    def _random_date(self, days_back: int = 365) -> datetime.datetime:
        """Generate a random date within the specified range."""
        end_date = datetime.datetime.now()
        start_date = end_date - datetime.timedelta(days=days_back)
        random_days = random.randint(0, days_back)
        return start_date + datetime.timedelta(days=random_days)
    
    def generate_complete_patient_dataset(self, 
                                        patient_count: int = 100,
                                        vitals_per_patient: int = 5,
                                        labs_per_patient: int = 3,
                                        notes_per_patient: int = 2) -> Dict[str, List]:
        """
        Generate a complete synthetic healthcare dataset.
        
        Args:
            patient_count: Number of patients to generate
            vitals_per_patient: Number of vital sign readings per patient
            labs_per_patient: Number of lab test panels per patient  
            notes_per_patient: Number of medical notes per patient
            
        Returns:
            Dictionary containing all generated healthcare data
        """
        dataset = {
            'patients': [],
            'vital_signs': [],
            'lab_results': [],
            'medical_notes': []
        }
        
        print(f"Generating synthetic healthcare data for {patient_count} patients...")
        
        for i in range(patient_count):
            if i % 10 == 0:
                print(f"  Generated {i}/{patient_count} patients...")
            
            # Generate patient record
            patient = self.generate_patient_record()
            dataset['patients'].append(asdict(patient))
            
            # Generate associated data
            vitals = self.generate_vital_signs(patient.patient_id, vitals_per_patient)
            dataset['vital_signs'].extend([asdict(v) for v in vitals])
            
            labs = self.generate_lab_results(patient.patient_id, labs_per_patient)
            dataset['lab_results'].extend([asdict(l) for l in labs])
            
            for _ in range(notes_per_patient):
                note = self.generate_medical_note(patient.patient_id)
                dataset['medical_notes'].append(asdict(note))
        
        print(f"Dataset generation complete!")
        print(f"  Patients: {len(dataset['patients'])}")
        print(f"  Vital Signs: {len(dataset['vital_signs'])}")
        print(f"  Lab Results: {len(dataset['lab_results'])}")
        print(f"  Medical Notes: {len(dataset['medical_notes'])}")
        
        return dataset
    
    def save_dataset_to_files(self, dataset: Dict[str, List], output_dir: str):
        """Save dataset to separate JSON and CSV files."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Save as JSON
        with open(os.path.join(output_dir, 'complete_dataset.json'), 'w') as f:
            json.dump(dataset, f, indent=2)
        
        # Save individual components as CSV
        for data_type, records in dataset.items():
            if records:
                df = pd.DataFrame(records)
                csv_path = os.path.join(output_dir, f'{data_type}.csv')
                df.to_csv(csv_path, index=False)
        
        print(f"Dataset saved to {output_dir}")
    
    def generate_hipaa_compliant_sample(self) -> bytes:
        """
        Generate a small HIPAA-compliant sample for encryption testing.
        
        Returns:
            Sample healthcare data as bytes for encryption testing
        """
        sample_patient = self.generate_patient_record()
        sample_vitals = self.generate_vital_signs(sample_patient.patient_id, 1)[0]
        sample_lab = self.generate_lab_results(sample_patient.patient_id, 1)[0]
        
        sample_data = {
            'patient': asdict(sample_patient),
            'vital_signs': asdict(sample_vitals),
            'lab_result': asdict(sample_lab)
        }
        
        return json.dumps(sample_data, indent=2).encode('utf-8')


class EncryptionDemoData:
    """
    Specialized data generator for CPDPM encryption demonstrations.
    """
    
    def __init__(self, generator: SyntheticHealthcareGenerator):
        """Initialize with a healthcare data generator."""
        self.generator = generator
    
    def create_encryption_test_cases(self) -> List[Tuple[str, bytes, str]]:
        """
        Create test cases specifically designed for encryption benchmarks.
        
        Returns:
            List of (description, data, context) tuples for testing
        """
        test_cases = []
        
        # Small patient record
        patient = self.generator.generate_patient_record()
        patient_data = json.dumps(asdict(patient), indent=2).encode('utf-8')
        context = f"patient:{patient.patient_id}"
        test_cases.append(("Single Patient Record", patient_data, context))
        
        # Vital signs batch
        vitals = self.generator.generate_vital_signs(patient.patient_id, 10)
        vitals_data = json.dumps([asdict(v) for v in vitals], indent=2).encode('utf-8')
        context = f"vitals:{patient.patient_id}:batch"
        test_cases.append(("Batch Vital Signs", vitals_data, context))
        
        # Lab results
        labs = self.generator.generate_lab_results(patient.patient_id, 5)
        labs_data = json.dumps([asdict(l) for l in labs], indent=2).encode('utf-8')
        context = f"labs:{patient.patient_id}:panel"
        test_cases.append(("Lab Results Panel", labs_data, context))
        
        # Medical note
        note = self.generator.generate_medical_note(patient.patient_id)
        note_data = json.dumps(asdict(note), indent=2).encode('utf-8')
        context = f"note:{patient.patient_id}:{note.note_type.replace(' ', '_')}"
        test_cases.append(("Medical Note", note_data, context))
        
        # Large dataset sample
        dataset = self.generator.generate_complete_patient_dataset(
            patient_count=5, vitals_per_patient=3, labs_per_patient=2, notes_per_patient=1
        )
        large_data = json.dumps(dataset, indent=2).encode('utf-8')
        context = "dataset:multi_patient:sample"
        test_cases.append(("Multi-Patient Dataset", large_data, context))
        
        return test_cases