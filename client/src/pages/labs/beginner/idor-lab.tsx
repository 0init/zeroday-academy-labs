import { useState, useEffect } from 'react';

interface Order {
  id: number;
  date: string;
  status: string;
  total: string;
}

export default function IdorLabPage() {
  const [orders, setOrders] = useState<Order[]>([]);
  const [selectedOrder, setSelectedOrder] = useState<any>(null);
  const [orderIdInput, setOrderIdInput] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMyOrders();
  }, []);

  const fetchMyOrders = async () => {
    try {
      const response = await fetch('/api/labs/idor/orders/my');
      const data = await response.json();
      setOrders(data.orders || []);
    } catch (err) {
      console.error('Failed to fetch orders');
    } finally {
      setLoading(false);
    }
  };

  const viewOrder = async (orderId: string) => {
    try {
      const response = await fetch(`/api/labs/idor/orders/${orderId}`);
      const data = await response.json();
      setSelectedOrder(data);
    } catch (err) {
      setSelectedOrder({ error: 'Failed to load order' });
    }
  };

  const handleViewOrder = (e: React.FormEvent) => {
    e.preventDefault();
    if (orderIdInput) {
      viewOrder(orderIdInput);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-indigo-600">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-white font-bold text-xl">ShopMax</span>
          </div>
          <div className="flex items-center gap-6 text-indigo-100 text-sm">
            <a href="#" className="hover:text-white">Home</a>
            <a href="#" className="hover:text-white">Products</a>
            <a href="#" className="hover:text-white">Orders</a>
            <a href="#" className="hover:text-white">Account</a>
            <div className="flex items-center gap-2 text-white">
              <div className="w-8 h-8 bg-indigo-500 rounded-full flex items-center justify-center">
                J
              </div>
              <span>John</span>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-6xl mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">My Orders</h1>
            <p className="text-gray-500">View and track your order history</p>
          </div>
          
          <form onSubmit={handleViewOrder} className="flex gap-2">
            <input
              type="text"
              value={orderIdInput}
              onChange={(e) => setOrderIdInput(e.target.value)}
              placeholder="Order ID (e.g., 1001)"
              className="px-4 py-2 border border-gray-300 rounded-lg text-gray-900 w-48"
            />
            <button
              type="submit"
              className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg"
            >
              Track Order
            </button>
          </form>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow-sm border">
              <div className="px-4 py-3 border-b">
                <h3 className="font-semibold text-gray-800">Your Orders</h3>
              </div>
              
              {loading ? (
                <div className="p-4 text-gray-500 text-center">Loading...</div>
              ) : (
                <div className="divide-y">
                  {orders.map((order) => (
                    <button
                      key={order.id}
                      onClick={() => viewOrder(order.id.toString())}
                      className={`w-full text-left p-4 hover:bg-gray-50 transition-colors ${
                        selectedOrder?.order?.id === order.id ? 'bg-indigo-50' : ''
                      }`}
                    >
                      <div className="flex justify-between items-start">
                        <div>
                          <div className="font-medium text-gray-900">Order #{order.id}</div>
                          <div className="text-sm text-gray-500">{order.date}</div>
                        </div>
                        <div className="text-right">
                          <div className="font-medium text-gray-900">{order.total}</div>
                          <span className={`text-xs px-2 py-1 rounded-full ${
                            order.status === 'Delivered' 
                              ? 'bg-green-100 text-green-800'
                              : order.status === 'Shipped'
                                ? 'bg-blue-100 text-blue-800'
                                : 'bg-yellow-100 text-yellow-800'
                          }`}>
                            {order.status}
                          </span>
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="lg:col-span-2">
            {selectedOrder ? (
              <div className="bg-white rounded-lg shadow-sm border overflow-hidden">
                {selectedOrder.error ? (
                  <div className="p-6">
                    <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-lg">
                      {selectedOrder.error}
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="bg-indigo-600 px-6 py-4">
                      <h2 className="text-white font-semibold text-lg">Order #{selectedOrder.order?.id}</h2>
                      <p className="text-indigo-100 text-sm">Placed on {selectedOrder.order?.date}</p>
                    </div>

                    <div className="p-6">
                      <div className="grid grid-cols-2 gap-6 mb-6">
                        <div>
                          <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Status</h4>
                          <span className={`inline-block px-3 py-1 rounded-full text-sm ${
                            selectedOrder.order?.status === 'Delivered'
                              ? 'bg-green-100 text-green-800'
                              : selectedOrder.order?.status === 'Shipped'
                                ? 'bg-blue-100 text-blue-800'
                                : 'bg-yellow-100 text-yellow-800'
                          }`}>
                            {selectedOrder.order?.status}
                          </span>
                        </div>
                        <div>
                          <h4 className="text-gray-500 text-xs font-medium uppercase mb-1">Total</h4>
                          <p className="text-gray-900 text-lg font-semibold">{selectedOrder.order?.total}</p>
                        </div>
                      </div>

                      <div className="border-t pt-4 mb-4">
                        <h4 className="font-semibold text-gray-800 mb-3">Shipping Address</h4>
                        <div className="bg-gray-50 rounded-lg p-4 text-sm text-gray-700">
                          <p>{selectedOrder.order?.shippingAddress?.name}</p>
                          <p>{selectedOrder.order?.shippingAddress?.street}</p>
                          <p>{selectedOrder.order?.shippingAddress?.city}, {selectedOrder.order?.shippingAddress?.state} {selectedOrder.order?.shippingAddress?.zip}</p>
                        </div>
                      </div>

                      {selectedOrder.order?.paymentMethod && (
                        <div className="border-t pt-4 mb-4">
                          <h4 className="font-semibold text-gray-800 mb-3">Payment Method</h4>
                          <div className="bg-gray-50 rounded-lg p-4 text-sm">
                            <p className="text-gray-700">{selectedOrder.order.paymentMethod.type}</p>
                            <p className="text-gray-900 font-mono">{selectedOrder.order.paymentMethod.last4}</p>
                            {selectedOrder.order.paymentMethod.fullNumber && (
                              <p className="text-red-600 font-mono text-xs mt-1">
                                Full: {selectedOrder.order.paymentMethod.fullNumber}
                              </p>
                            )}
                          </div>
                        </div>
                      )}

                      <div className="border-t pt-4">
                        <h4 className="font-semibold text-gray-800 mb-3">Items</h4>
                        <div className="space-y-3">
                          {selectedOrder.order?.items?.map((item: any, idx: number) => (
                            <div key={idx} className="flex justify-between items-center bg-gray-50 rounded-lg p-3">
                              <div>
                                <p className="font-medium text-gray-900">{item.name}</p>
                                <p className="text-sm text-gray-500">Qty: {item.quantity}</p>
                              </div>
                              <p className="font-medium text-gray-900">{item.price}</p>
                            </div>
                          ))}
                        </div>
                      </div>

                      {selectedOrder.flag && (
                        <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                          <p className="text-yellow-700 font-mono text-sm">{selectedOrder.flag}</p>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="bg-white rounded-lg shadow-sm border p-12 text-center">
                <div className="text-gray-400 text-6xl mb-4">📦</div>
                <h3 className="text-gray-600 font-medium">Select an Order</h3>
                <p className="text-gray-400 text-sm mt-1">
                  Click on an order from the list or enter an order ID to view details
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      <footer className="bg-gray-800 py-6 mt-12">
        <div className="max-w-6xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>ShopMax © 2024. Your trusted online marketplace.</p>
        </div>
      </footer>
    </div>
  );
}
