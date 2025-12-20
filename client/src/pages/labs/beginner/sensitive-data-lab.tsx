import { useState, useEffect } from 'react';

interface Patient {
  id: number;
  name: string;
  dob: string;
  appointment: string;
  doctor: string;
}

export default function SensitiveDataLabPage() {
  const [patients, setPatients] = useState<Patient[]>([]);
  const [selectedPatient, setSelectedPatient] = useState<any>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchPatients();
  }, []);

  const fetchPatients = async () => {
    try {
      const response = await fetch('/api/labs/sensitive/patients');
      const data = await response.json();
      setPatients(data.patients || []);
    } catch (err) {
      console.error('Failed to fetch patients');
    } finally {
      setLoading(false);
    }
  };

  const viewPatient = async (id: number) => {
    try {
      const response = await fetch(`/api/labs/sensitive/patients/${id}`);
      const data = await response.json();
      setSelectedPatient(data);
    } catch (err) {
      console.error('Failed to fetch patient details');
    }
  };

  const filteredPatients = patients.filter(p => 
    p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    p.id.toString().includes(searchTerm)
  );

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-teal-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold">+</span>
            </div>
            <div>
              <span className="text-gray-800 font-semibold text-lg block">HealthCare Portal</span>
              <span className="text-gray-500 text-xs">Patient Management System</span>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-gray-600 text-sm">Dr. Smith</span>
            <div className="w-8 h-8 bg-gray-300 rounded-full"></div>
          </div>
        </div>
      </nav>

      <div className="max-w-6xl mx-auto px-4 py-6">
        <div className="flex gap-6">
          <div className="w-80 flex-shrink-0">
            <div className="bg-white rounded-lg shadow-sm border p-4">
              <h2 className="text-gray-800 font-semibold mb-4">Patient List</h2>
              
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search patients..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg mb-4 text-gray-900 text-sm"
              />

              {loading ? (
                <div className="text-gray-500 text-sm text-center py-4">Loading...</div>
              ) : (
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {filteredPatients.map((patient) => (
                    <button
                      key={patient.id}
                      onClick={() => viewPatient(patient.id)}
                      className={`w-full text-left p-3 rounded-lg border transition-colors ${
                        selectedPatient?.patient?.id === patient.id
                          ? 'bg-teal-50 border-teal-300'
                          : 'bg-gray-50 border-gray-200 hover:bg-gray-100'
                      }`}
                    >
                      <div className="font-medium text-gray-900 text-sm">{patient.name}</div>
                      <div className="text-gray-500 text-xs mt-1">ID: {patient.id}</div>
                      <div className="text-gray-500 text-xs">Next: {patient.appointment}</div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="flex-1">
            {selectedPatient ? (
              <div className="bg-white rounded-lg shadow-sm border">
                <div className="bg-teal-600 px-6 py-4 rounded-t-lg">
                  <h2 className="text-white font-semibold text-lg">Patient Record</h2>
                  <p className="text-teal-100 text-sm">Confidential Medical Information</p>
                </div>

                <div className="p-6">
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">Full Name</h3>
                      <p className="text-gray-900">{selectedPatient.patient?.name}</p>
                    </div>
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">Patient ID</h3>
                      <p className="text-gray-900 font-mono">{selectedPatient.patient?.id}</p>
                    </div>
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">Date of Birth</h3>
                      <p className="text-gray-900">{selectedPatient.patient?.dob}</p>
                    </div>
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">Phone</h3>
                      <p className="text-gray-900">{selectedPatient.patient?.phone}</p>
                    </div>
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">Email</h3>
                      <p className="text-gray-900">{selectedPatient.patient?.email}</p>
                    </div>
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">SSN</h3>
                      <p className="text-gray-900 font-mono">{selectedPatient.patient?.ssn}</p>
                    </div>
                  </div>

                  {selectedPatient.patient?.medicalHistory && (
                    <div className="mt-6 pt-6 border-t">
                      <h3 className="text-gray-800 font-semibold mb-3">Medical History</h3>
                      <div className="bg-gray-50 rounded-lg p-4">
                        <div className="space-y-2 text-sm">
                          <div className="flex justify-between">
                            <span className="text-gray-600">Blood Type:</span>
                            <span className="text-gray-900">{selectedPatient.patient.medicalHistory.bloodType}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-600">Allergies:</span>
                            <span className="text-gray-900">{selectedPatient.patient.medicalHistory.allergies?.join(', ') || 'None'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-600">Conditions:</span>
                            <span className="text-gray-900">{selectedPatient.patient.medicalHistory.conditions?.join(', ') || 'None'}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {selectedPatient.patient?.insurance && (
                    <div className="mt-6 pt-6 border-t">
                      <h3 className="text-gray-800 font-semibold mb-3">Insurance Information</h3>
                      <div className="bg-gray-50 rounded-lg p-4">
                        <div className="space-y-2 text-sm">
                          <div className="flex justify-between">
                            <span className="text-gray-600">Provider:</span>
                            <span className="text-gray-900">{selectedPatient.patient.insurance.provider}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-600">Policy Number:</span>
                            <span className="text-gray-900 font-mono">{selectedPatient.patient.insurance.policyNumber}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-600">Group Number:</span>
                            <span className="text-gray-900 font-mono">{selectedPatient.patient.insurance.groupNumber}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {selectedPatient.flag && (
                    <div className="mt-6 pt-6 border-t">
                      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                        <h4 className="text-yellow-800 font-medium text-sm">System Notice</h4>
                        <p className="text-yellow-700 text-sm mt-1 font-mono">{selectedPatient.flag}</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-white rounded-lg shadow-sm border p-12 text-center">
                <div className="text-gray-400 text-6xl mb-4">📋</div>
                <h3 className="text-gray-600 font-medium">Select a Patient</h3>
                <p className="text-gray-400 text-sm mt-1">Choose a patient from the list to view their records</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <footer className="bg-white border-t py-4 mt-8">
        <div className="max-w-6xl mx-auto px-4 text-center text-gray-500 text-xs">
          <p>HealthCare Portal © 2024. HIPAA Compliant. For authorized medical personnel only.</p>
        </div>
      </footer>
    </div>
  );
}
