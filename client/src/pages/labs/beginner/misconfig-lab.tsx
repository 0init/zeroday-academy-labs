import { useState } from 'react';

export default function MisconfigLabPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await fetch(`/api/labs/misconfig/search?q=${encodeURIComponent(searchQuery)}`);
      const data = await response.json();
      setSearchResults(data);
    } catch (err) {
      setSearchResults({ error: 'Search failed' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-white">
      <nav className="bg-gray-50 border-b">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-green-600 rounded flex items-center justify-center">
              <span className="text-white font-bold text-sm">E</span>
            </div>
            <span className="text-gray-800 font-semibold">EcoShop</span>
          </div>
          <div className="flex items-center gap-4 text-gray-600 text-sm">
            <a href="#" className="hover:text-green-600">Products</a>
            <a href="#" className="hover:text-green-600">About</a>
            <a href="#" className="hover:text-green-600">Contact</a>
            <a href="#" className="hover:text-green-600">Cart (0)</a>
          </div>
        </div>
      </nav>

      <div className="bg-green-600 py-16">
        <div className="max-w-3xl mx-auto px-4 text-center">
          <h1 className="text-white text-3xl font-bold mb-4">Sustainable Living Starts Here</h1>
          <p className="text-green-100 mb-8">Discover eco-friendly products for a greener tomorrow</p>
          
          <form onSubmit={handleSearch} className="max-w-xl mx-auto">
            <div className="flex gap-2">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search for products..."
                className="flex-1 px-4 py-3 rounded-lg text-gray-900"
              />
              <button
                type="submit"
                disabled={loading}
                className="bg-green-800 hover:bg-green-900 text-white font-medium px-6 py-3 rounded-lg transition-colors"
              >
                {loading ? 'Searching...' : 'Search'}
              </button>
            </div>
          </form>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-4 py-8">
        {searchResults && (
          <div className="mb-8">
            {searchResults.error ? (
              <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-lg">
                <h3 className="font-semibold mb-2">Error</h3>
                <pre className="text-sm font-mono whitespace-pre-wrap">{searchResults.error}</pre>
                {searchResults.stack && (
                  <pre className="text-xs font-mono mt-2 p-2 bg-red-100 rounded overflow-x-auto">{searchResults.stack}</pre>
                )}
                {searchResults.debug && (
                  <div className="mt-4 p-3 bg-red-100 rounded">
                    <h4 className="font-medium text-sm mb-2">Debug Information:</h4>
                    <pre className="text-xs font-mono">{JSON.stringify(searchResults.debug, null, 2)}</pre>
                  </div>
                )}
              </div>
            ) : searchResults.products?.length > 0 ? (
              <div>
                <h2 className="text-gray-800 font-semibold mb-4">Search Results for "{searchQuery}"</h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {searchResults.products.map((product: any) => (
                    <div key={product.id} className="bg-white rounded-lg shadow-sm border p-4">
                      <div className="h-32 bg-gray-100 rounded mb-3"></div>
                      <h3 className="text-gray-900 font-medium">{product.name}</h3>
                      <p className="text-green-600 font-semibold mt-1">${product.price}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                No products found for "{searchQuery}"
              </div>
            )}
          </div>
        )}

        <h2 className="text-gray-800 font-semibold text-xl mb-6">Featured Products</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          {[
            { name: 'Bamboo Toothbrush Set', price: '12.99' },
            { name: 'Reusable Produce Bags', price: '15.99' },
            { name: 'Stainless Steel Straws', price: '8.99' },
            { name: 'Organic Cotton Tote', price: '22.99' },
          ].map((product, idx) => (
            <div key={idx} className="bg-white rounded-lg shadow-sm border overflow-hidden">
              <div className="h-40 bg-gray-100"></div>
              <div className="p-4">
                <h3 className="text-gray-900 font-medium text-sm">{product.name}</h3>
                <p className="text-green-600 font-semibold mt-1">${product.price}</p>
                <button className="mt-3 w-full bg-green-600 hover:bg-green-700 text-white py-2 rounded text-sm">
                  Add to Cart
                </button>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-12 bg-gray-50 rounded-lg p-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
            <div>
              <div className="text-3xl mb-2">🌱</div>
              <h3 className="text-gray-900 font-semibold">Eco-Friendly</h3>
              <p className="text-gray-500 text-sm mt-1">All products are sustainably sourced</p>
            </div>
            <div>
              <div className="text-3xl mb-2">📦</div>
              <h3 className="text-gray-900 font-semibold">Free Shipping</h3>
              <p className="text-gray-500 text-sm mt-1">On orders over $50</p>
            </div>
            <div>
              <div className="text-3xl mb-2">♻️</div>
              <h3 className="text-gray-900 font-semibold">Zero Waste</h3>
              <p className="text-gray-500 text-sm mt-1">Plastic-free packaging</p>
            </div>
          </div>
        </div>
      </div>

      <footer className="bg-gray-800 py-8 mt-12">
        <div className="max-w-5xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>EcoShop © 2024. Making the world greener, one product at a time.</p>
          <div className="mt-4 flex justify-center gap-6">
            <a href="#" className="hover:text-white">Privacy Policy</a>
            <a href="#" className="hover:text-white">Terms of Service</a>
            <a href="#" className="hover:text-white">Contact Us</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
