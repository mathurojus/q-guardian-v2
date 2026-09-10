import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import { MessageSquare, X, Send, Bot } from 'lucide-react';
import { API_BASE } from '../lib/api.js';

const Chatbot = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState([
        { role: 'bot', text: 'Hello! I am the Q-Guardian intelligence assistant. I analyze your scans locally without external models. How can I help you today?' }
    ]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const messagesEndRef = useRef(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const handleSend = async (text) => {
        const query = text || input;
        if (!query.trim()) return;

        setMessages(prev => [...prev, { role: 'user', text: query }]);
        setInput('');
        setIsTyping(true);

        try {
            const res = await axios.post(`${API_BASE}/chat`, { message: query });
            setTimeout(() => {
                setMessages(prev => [...prev, { role: 'bot', text: res.data.reply }]);
                setIsTyping(false);
            }, 500); // Small artificial delay for natural feel
        } catch (err) {
            setIsTyping(false);
            setMessages(prev => [...prev, { role: 'bot', text: "Sorry, I am currently offline or disconnected from the engine." }]);
        }
    };

    return (
        <div className="fixed bottom-12 right-6 z-50">
            {/* Chatbot Button */}
            {!isOpen && (
                <button 
                    onClick={() => setIsOpen(true)}
                    className="bg-cobalt-600 text-white p-4 rounded-full shadow-[0_8px_24px_-8px_rgba(79,70,229,0.6)] hover:bg-cobalt-700 transition-all transform hover:scale-105"
                    aria-label="Open Q-Guardian assistant"
                >
                    <MessageSquare size={22} />
                </button>
            )}

            {/* Chatbot Window */}
            {isOpen && (
                <div className="w-80 sm:w-96 h-[500px] glass-card flex flex-col overflow-hidden shadow-[0_24px_48px_-16px_rgba(15,23,42,0.25)] animate-in slide-in-from-bottom-10 fade-in duration-300">
                    {/* Header */}
                    <div className="border-b border-slate-200 bg-slate-50/70 p-4 flex justify-between items-center">
                        <div className="flex items-center gap-2.5">
                            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cobalt-600 text-white">
                                <Bot size={18} />
                            </div>
                            <div>
                                <h3 className="font-bold text-sm tracking-tight text-slate-900">Q-Guardian AI</h3>
                                <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400">On-device secure engine</p>
                            </div>
                        </div>
                        <button onClick={() => setIsOpen(false)} className="p-1.5 rounded-md text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 transition-colors">
                            <X size={18} />
                        </button>
                    </div>

                    {/* Messages Area */}
                    <div className="flex-1 p-4 overflow-y-auto bg-slate-50 space-y-4">
                        {messages.map((msg, i) => (
                            <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                <div className={`max-w-[85%] text-sm p-3 rounded-xl text-[13px] leading-relaxed ${
                                    msg.role === 'user' 
                                        ? 'bg-slate-900 text-white rounded-tr-none'
                                        : 'bg-white text-slate-700 border border-slate-200 rounded-tl-none'
                                }`}>
                                    {msg.text}
                                </div>
                            </div>
                        ))}
                        {isTyping && (
                            <div className="flex justify-start">
                                <div className="bg-white p-3 rounded-xl rounded-tl-none border border-slate-200 flex items-center gap-1">
                                    <div className="w-2 h-2 bg-slate-300 rounded-full animate-bounce"></div>
                                    <div className="w-2 h-2 bg-slate-300 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                                    <div className="w-2 h-2 bg-slate-300 rounded-full animate-bounce" style={{animationDelay: '0.4s'}}></div>
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Quick Queries */}
                    <div className="px-4 py-2 bg-white flex gap-2 overflow-x-auto scrollbar-hide border-t border-slate-200">
                        <button onClick={() => handleSend("What is MOSCA?")} className="shrink-0 text-[10px] font-bold bg-white text-cobalt-700 border border-cobalt-100 rounded-full px-3 py-1 hover:bg-cobalt-600 hover:text-white hover:border-cobalt-600 transition-colors">What is MOSCA?</button>
                        <button onClick={() => handleSend("Scan results")} className="shrink-0 text-[10px] font-bold bg-white text-cobalt-700 border border-cobalt-100 rounded-full px-3 py-1 hover:bg-cobalt-600 hover:text-white hover:border-cobalt-600 transition-colors">Latest Scan</button>
                        <button onClick={() => handleSend("Are we RBI compliant?")} className="shrink-0 text-[10px] font-bold bg-white text-cobalt-700 border border-cobalt-100 rounded-full px-3 py-1 hover:bg-cobalt-600 hover:text-white hover:border-cobalt-600 transition-colors">RBI Compliance</button>
                    </div>

                    {/* Input Area */}
                    <div className="p-3 bg-white border-t border-slate-200 flex gap-2">
                        <input 
                            type="text" 
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyPress={(e) => e.key === 'Enter' && handleSend()}
                            placeholder="Ask me anything..."
                            className="flex-1 text-sm px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:border-cobalt-500 focus:ring-2 focus:ring-cobalt-100"
                        />
                        <button 
                            onClick={() => handleSend()}
                            disabled={!input.trim()}
                            className="bg-cobalt-600 text-white p-2.5 rounded-lg disabled:opacity-40 hover:bg-cobalt-700 transition-colors"
                        >
                            <Send size={16} />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Chatbot;
