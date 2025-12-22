import { useState, useEffect } from 'react';

interface Comment {
  id: number;
  author: string;
  content: string;
  timestamp: string;
  avatar: string;
}

export default function XssLabPage() {
  const [comments, setComments] = useState<Comment[]>([]);
  const [name, setName] = useState('');
  const [comment, setComment] = useState('');
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResult, setSearchResult] = useState('');
  const [storedXssFlag, setStoredXssFlag] = useState('');
  const [reflectedXssFlag, setReflectedXssFlag] = useState('');

  useEffect(() => {
    fetchComments();
  }, []);

  const fetchComments = async () => {
    try {
      const response = await fetch('/api/labs/xss/comments');
      const data = await response.json();
      setComments(data.comments || []);
    } catch (err) {
      console.error('Failed to fetch comments');
    }
  };

  const handleSubmitComment = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await fetch('/api/labs/xss/comments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ author: name, content: comment })
      });
      
      const data = await response.json();
      if (data.success) {
        setName('');
        setComment('');
        fetchComments();
        if (data.flag) {
          setStoredXssFlag(data.flag);
        }
      }
    } catch (err) {
      console.error('Failed to post comment');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch(`/api/labs/xss/search?q=${encodeURIComponent(searchQuery)}`);
      const data = await response.json();
      setSearchResult(data.html || '');
      if (data.flag) {
        setReflectedXssFlag(data.flag);
      }
    } catch (err) {
      console.error('Search failed');
    }
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-orange-500 rounded flex items-center justify-center">
              <span className="text-white font-bold text-sm">TB</span>
            </div>
            <span className="text-gray-800 font-semibold text-lg">TechBlog</span>
          </div>
          <div className="flex items-center gap-4 text-gray-600 text-sm">
            <a href="#" className="hover:text-orange-500">Home</a>
            <a href="#" className="hover:text-orange-500">Articles</a>
            <a href="#" className="hover:text-orange-500">About</a>
          </div>
        </div>
      </nav>

      <div className="max-w-5xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <article className="bg-white rounded-lg shadow-md overflow-hidden">
              <img 
                src="https://images.unsplash.com/photo-1461749280684-dccba630e2f6?w=800&h=400&fit=crop" 
                alt="Article header"
                className="w-full h-48 object-cover"
              />
              <div className="p-6">
                <span className="text-orange-500 text-sm font-medium">Technology</span>
                <h1 className="text-2xl font-bold text-gray-900 mt-2">The Future of Web Security in 2024</h1>
                <p className="text-gray-500 text-sm mt-2">Published on January 15, 2024 • 8 min read</p>
                
                <div className="prose prose-gray mt-4">
                  <p className="text-gray-700">
                    As we move further into 2024, web security continues to evolve at a rapid pace. 
                    New vulnerabilities are discovered daily, and organizations must stay vigilant 
                    to protect their users and data.
                  </p>
                  <p className="text-gray-700 mt-4">
                    One of the most common attack vectors remains Cross-Site Scripting (XSS), 
                    which allows attackers to inject malicious scripts into trusted websites. 
                    These attacks can lead to session hijacking, credential theft, and more.
                  </p>
                </div>
              </div>
            </article>

            <div className="bg-white rounded-lg shadow-md mt-8 p-6">
              <h2 className="text-xl font-bold text-gray-900 mb-6">Comments ({comments.length})</h2>
              
              {storedXssFlag && (
                <div className="bg-green-100 border border-green-300 rounded-lg p-4 mb-6">
                  <h3 className="text-green-800 font-semibold">Stored XSS Successful!</h3>
                  <p className="text-green-700 font-mono text-sm mt-1">{storedXssFlag}</p>
                </div>
              )}

              <form onSubmit={handleSubmitComment} className="mb-8 border-b pb-6">
                <h3 className="text-gray-700 font-medium mb-4">Leave a comment</h3>
                <div className="space-y-4">
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Your name"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-orange-500 text-gray-900"
                    required
                  />
                  <textarea
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    placeholder="Write your comment..."
                    rows={4}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-orange-500 text-gray-900"
                    required
                  />
                  <button
                    type="submit"
                    disabled={loading}
                    className="bg-orange-500 hover:bg-orange-600 text-white font-medium px-6 py-2 rounded-lg transition-colors disabled:opacity-50"
                  >
                    {loading ? 'Posting...' : 'Post Comment'}
                  </button>
                </div>
              </form>

              <div className="space-y-6">
                {comments.map((c) => (
                  <div key={c.id} className="flex gap-4">
                    <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center text-gray-600 font-medium">
                      {c.avatar || c.author.charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span 
                          className="font-medium text-gray-900"
                          dangerouslySetInnerHTML={{ __html: c.author }}
                        />
                        <span className="text-gray-400 text-sm">{c.timestamp}</span>
                      </div>
                      <div 
                        className="text-gray-700 mt-1"
                        dangerouslySetInnerHTML={{ __html: c.content }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <aside className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow-md p-6 mb-6">
              <h3 className="text-gray-900 font-semibold mb-4">Search Articles</h3>
              <form onSubmit={handleSearch}>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search..."
                    className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-gray-900 text-sm"
                  />
                  <button
                    type="submit"
                    className="bg-orange-500 hover:bg-orange-600 text-white px-4 py-2 rounded-lg text-sm"
                  >
                    Go
                  </button>
                </div>
              </form>
              {reflectedXssFlag && (
                <div className="mt-4 bg-green-100 border border-green-300 rounded p-3">
                  <p className="text-green-800 font-semibold text-sm">Reflected XSS Successful!</p>
                  <p className="text-green-700 font-mono text-xs mt-1">{reflectedXssFlag}</p>
                </div>
              )}
              {searchResult && (
                <div 
                  className="mt-4 p-3 bg-gray-50 rounded text-sm"
                  dangerouslySetInnerHTML={{ __html: searchResult }}
                />
              )}
            </div>

            <div className="bg-white rounded-lg shadow-md p-6 mb-6">
              <h3 className="text-gray-900 font-semibold mb-4">Popular Tags</h3>
              <div className="flex flex-wrap gap-2">
                <span className="bg-gray-100 text-gray-600 px-3 py-1 rounded-full text-sm">Security</span>
                <span className="bg-gray-100 text-gray-600 px-3 py-1 rounded-full text-sm">JavaScript</span>
                <span className="bg-gray-100 text-gray-600 px-3 py-1 rounded-full text-sm">Web Dev</span>
                <span className="bg-gray-100 text-gray-600 px-3 py-1 rounded-full text-sm">XSS</span>
                <span className="bg-gray-100 text-gray-600 px-3 py-1 rounded-full text-sm">OWASP</span>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-md p-6">
              <h3 className="text-gray-900 font-semibold mb-4">Newsletter</h3>
              <p className="text-gray-600 text-sm mb-3">Get the latest security news delivered to your inbox.</p>
              <input
                type="email"
                placeholder="your@email.com"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-gray-900 text-sm mb-2"
              />
              <button className="w-full bg-gray-800 hover:bg-gray-900 text-white py-2 rounded-lg text-sm">
                Subscribe
              </button>
            </div>
          </aside>
        </div>
      </div>

      <footer className="bg-gray-800 py-6 mt-12">
        <div className="max-w-5xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>© 2024 TechBlog. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}
