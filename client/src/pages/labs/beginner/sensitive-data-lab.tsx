import { useState, useEffect } from 'react';

interface Appointment {
  id: string;
  name: string;
  appointment: string;
  doctor: string;
}

export default function SensitiveDataLabPage() {
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [selectedPatient, setSelectedPatient] = useState<any>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAppointments();
  }, []);

  const fetchAppointments = async () => {
    try {
      const response = await fetch('/api/labs/sensitive/appointments');
      const data = await response.json();
      setAppointments(data.appointments || []);
    } catch (err) {
      console.error('Failed to fetch appointments');
    } finally {
      setLoading(false);
    }
  };

  const viewPatient = async (id: string) => {
    try {
      const response = await fetch(`/api/labs/sensitive/patient/${id}`);
      const data = await response.json();
      setSelectedPatient(data);
    } catch (err) {
      console.error('Failed to fetch patient details');
    }
  };

  const filteredAppointments = appointments.filter(a => 
    a.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-teal-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">+</span>
            </div>
            <div>
              <span className="text-gray-800 font-semibold text-lg block">HealthCare Plus</span>
              <span className="text-gray-500 text-xs">Patient Management System v3.2.1</span>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-gray-600 text-sm">Dr. Smith (Receptionist View)</span>
            <div className="w-8 h-8 bg-gray-300 rounded-full"></div>
          </div>
        </div>
      </nav>

      <div className="max-w-6xl mx-auto px-4 py-6">
        <div className="flex gap-6">
          <div className="w-80 flex-shrink-0">
            <div className="bg-white rounded-lg shadow-sm border p-4">
              <h2 className="text-gray-800 font-semibold mb-4">Today's Appointments</h2>
              
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by name or ID..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg mb-4 text-gray-900 text-sm"
              />

              {loading ? (
                <div className="text-gray-500 text-sm text-center py-4">Loading...</div>
              ) : (
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {filteredAppointments.map((apt) => (
                    <button
                      key={apt.id}
                      onClick={() => viewPatient(apt.id)}
                      className={`w-full text-left p-3 rounded-lg border transition-colors ${
                        selectedPatient?.patient?.id === apt.id
                          ? 'bg-teal-50 border-teal-300'
                          : 'bg-gray-50 border-gray-200 hover:bg-gray-100'
                      }`}
                    >
                      <div className="font-medium text-gray-900 text-sm">{apt.name}</div>
                      <div className="text-gray-500 text-xs mt-1">ID: {apt.id}</div>
                      <div className="text-gray-500 text-xs">Appt: {apt.appointment}</div>
                      <div className="text-gray-500 text-xs">{apt.doctor}</div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="flex-1">
            {selectedPatient?.patient ? (
              <div className="bg-white rounded-lg shadow-sm border">
                <div className="bg-teal-600 px-6 py-4 rounded-t-lg">
                  <h2 className="text-white font-semibold text-lg">Appointment Details</h2>
                  <p className="text-teal-100 text-sm">Limited View - Receptionist Access</p>
                </div>

                <div className="p-6">
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">Patient Name</h3>
                      <p className="text-gray-900">{selectedPatient.patient.name}</p>
                    </div>
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">Patient ID</h3>
                      <p className="text-gray-900 font-mono">{selectedPatient.patient.id}</p>
                    </div>
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">Appointment Date</h3>
                      <p className="text-gray-900">{selectedPatient.patient.appointment}</p>
                    </div>
                    <div>
                      <h3 className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-1">Assigned Doctor</h3>
                      <p className="text-gray-900">{selectedPatient.patient.doctor}</p>
                    </div>
                  </div>

                  <div className="mt-6 pt-6 border-t">
                    <div className="bg-gray-100 rounded-lg p-4 text-center">
                      <p className="text-gray-500 text-sm">
                        Additional patient information requires elevated access permissions.
                      </p>
                      <p className="text-gray-400 text-xs mt-2">
                        Contact system administrator for full record access.
                      </p>
                    </div>
                  </div>

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
                <h3 className="text-gray-600 font-medium">Select an Appointment</h3>
                <p className="text-gray-400 text-sm mt-1">Choose an appointment from the list to view details</p>
              </div>
            )}
          </div>
        </div>

        <div className="mt-8 bg-white rounded-lg shadow-sm border p-6">
          <h3 className="text-gray-800 font-semibold mb-4">Quick Actions</h3>
          <div className="grid grid-cols-4 gap-4">
            <button className="bg-gray-100 hover:bg-gray-200 text-gray-700 py-3 px-4 rounded-lg text-sm transition-colors">
              Schedule New
            </button>
            <button className="bg-gray-100 hover:bg-gray-200 text-gray-700 py-3 px-4 rounded-lg text-sm transition-colors">
              Check-in Patient
            </button>
            <button className="bg-gray-100 hover:bg-gray-200 text-gray-700 py-3 px-4 rounded-lg text-sm transition-colors">
              View Calendar
            </button>
            <button className="bg-gray-100 hover:bg-gray-200 text-gray-700 py-3 px-4 rounded-lg text-sm transition-colors">
              Reports
            </button>
          </div>
        </div>
      </div>

      <footer className="bg-white border-t py-4 mt-8">
        <div className="max-w-6xl mx-auto px-4 text-center text-gray-500 text-xs">
          <p>HealthCare Plus © 2024. HIPAA Compliant. For authorized medical personnel only.</p>
          <p className="mt-1">System API v3.2.1 | Build 2024.01.15</p>
        </div>
      </footer>
    </div>
  );
}
