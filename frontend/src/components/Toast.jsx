import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, CheckCircle, AlertCircle, Info } from 'lucide-react';

const Toast = ({ message, type, onClose }) => {
  const stylesData = {
    success: {
      bg: 'bg-green-50',
      border: 'border-green-500',
      text: 'text-green-800',
      icon: <CheckCircle className="text-green-500" size={18} />
    },
    error: {
      bg: 'bg-red-50',
      border: 'border-red-500',
      text: 'text-red-800',
      icon: <AlertCircle className="text-red-500" size={18} />
    },
    info: {
      bg: 'bg-blue-50',
      border: 'border-blue-500',
      text: 'text-blue-800',
      icon: <Info className="text-blue-500" size={18} />
    }
  };
  
  const styles = stylesData[type] || stylesData.info;

  return (
    <motion.div
      initial={{ opacity: 0, x: 50, scale: 0.9 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 20, scale: 0.9 }}
      className={`flex items-center gap-3 px-4 py-3 rounded-lg border shadow-lg ${styles.bg} ${styles.border} min-w-[300px] max-w-md`}
    >
      <div className="flex-shrink-0">{styles.icon}</div>
      <div className={`flex-grow text-xs font-bold uppercase tracking-tight ${styles.text}`}>
        {message}
      </div>
      <button 
        onClick={onClose}
        className="flex-shrink-0 p-1 hover:bg-black/5 rounded transition-colors"
      >
        <X size={14} className={styles.text} />
      </button>
    </motion.div>
  );
};

export default Toast;
