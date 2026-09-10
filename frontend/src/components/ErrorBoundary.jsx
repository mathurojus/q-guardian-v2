import React, { Component } from 'react';
import { AlertTriangle } from 'lucide-react';

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({
      error: error,
      errorInfo: errorInfo
    });
    console.error("Uncaught error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="w-full flex items-center justify-center p-8 min-h-[40vh]">
          <div className="glass-card p-8 border-l-4 border-red-500 text-red-600 bg-red-50 flex flex-col items-center max-w-lg w-full text-center">
            <AlertTriangle size={48} className="text-red-500 mb-4" />
            <h2 className="text-xl font-black uppercase mb-2">System Error</h2>
            <p className="text-sm text-red-800 font-bold mb-4">An unexpected error crashed this module.</p>
            <details className="text-left w-full bg-white/50 p-4 rounded text-xs font-mono overflow-auto max-h-48 whitespace-pre-wrap">
               <summary className="cursor-pointer font-bold mb-2">View Technical Details</summary>
               {this.state.error && this.state.error.toString()}
               <br />
               {this.state.errorInfo && this.state.errorInfo.componentStack}
            </details>
            <button 
              onClick={() => window.location.reload()} 
              className="mt-6 bg-cobalt-600 text-white font-bold uppercase py-2 px-8 rounded hover:bg-cobalt-700 transition-colors text-sm"
            >
              Reset Platform
            </button>
          </div>
        </div>
      );
    }

    return this.props.children; 
  }
}

export default ErrorBoundary;
