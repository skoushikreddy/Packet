/**
 * NetScope — Wireshark-Grade Filter Bar (Graphite Minimal Theme)
 */

import React, { useState, useEffect } from 'react';
import { Search, CheckCircle2, AlertTriangle, X, ChevronDown, Sparkles } from 'lucide-react';
import { validateFilter, FILTER_PRESETS } from '../utils/filterEngine';

interface FilterBarProps {
  currentFilter: string;
  onApplyFilter: (filter: string) => void;
  matchingCount: number;
  totalCount: number;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  currentFilter,
  onApplyFilter,
  matchingCount,
  totalCount,
}) => {
  const [inputValue, setInputValue] = useState(currentFilter);
  const [validation, setValidation] = useState<{ isValid: boolean; error?: string }>({ isValid: true });
  const [showPresets, setShowPresets] = useState(false);

  useEffect(() => {
    setInputValue(currentFilter);
    setValidation(validateFilter(currentFilter));
  }, [currentFilter]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setInputValue(val);
    const result = validateFilter(val);
    setValidation(result);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      if (validation.isValid) {
        onApplyFilter(inputValue.trim());
      }
    } else if (e.key === 'Escape') {
      setInputValue('');
      onApplyFilter('');
    }
  };

  const handleSelectPreset = (query: string) => {
    setInputValue(query);
    setValidation(validateFilter(query));
    onApplyFilter(query);
    setShowPresets(false);
  };

  const handleClear = () => {
    setInputValue('');
    setValidation({ isValid: true });
    onApplyFilter('');
  };

  return (
    <div className="relative flex flex-col space-y-1.5 w-full">
      <div className="flex items-center space-x-2">
        {/* Input Container */}
        <div 
          className={`flex-1 flex items-center bg-[#202429] border rounded-lg px-3 py-1.5 transition-colors ${
            !validation.isValid && inputValue
              ? 'border-[#F87171] ring-1 ring-[#F87171]/30'
              : inputValue && validation.isValid
              ? 'border-[#34D399] ring-1 ring-[#34D399]/30'
              : 'border-[#454B53] focus-within:border-[#60A5FA]'
          }`}
        >
          <Search className="w-4 h-4 text-[#7F8996] mr-2 shrink-0" />
          <input
            type="text"
            value={inputValue}
            onChange={handleChange}
            onKeyDown={handleKeyDown}
            placeholder="Apply a display filter... (e.g. tcp, udp, dns, ip.src == 192.168.1.1, tcp.port == 443)"
            className="w-full bg-transparent text-xs text-[#F3F4F6] placeholder-[#7F8996] font-mono outline-none"
          />

          {inputValue && (
            <button
              onClick={handleClear}
              className="p-1 text-[#7F8996] hover:text-[#D1D5DB] transition rounded"
              title="Clear Filter"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Syntax Validation Status Indicator */}
          {inputValue && (
            <div className="ml-2 flex items-center">
              {validation.isValid ? (
                <span title="Valid expression">
                  <CheckCircle2 className="w-4 h-4 text-[#34D399]" />
                </span>
              ) : (
                <span title="Invalid syntax">
                  <AlertTriangle className="w-4 h-4 text-[#F87171]" />
                </span>
              )}
            </div>
          )}
        </div>

        {/* Apply Button */}
        <button
          onClick={() => validation.isValid && onApplyFilter(inputValue.trim())}
          disabled={!validation.isValid}
          className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#30353B] hover:bg-[#383E45] border border-[#454B53] text-[#F3F4F6] disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
        >
          Apply
        </button>

        {/* Presets Dropdown Toggle */}
        <div className="relative">
          <button
            onClick={() => setShowPresets(!showPresets)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#292E34] hover:bg-[#383E45] border border-[#454B53] text-[#D1D5DB] transition-colors cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5 text-[#94A3B8]" />
            <span>Presets</span>
            <ChevronDown className="w-3 h-3 text-[#7F8996]" />
          </button>

          {showPresets && (
            <div className="absolute right-0 mt-2 w-72 bg-[#292E34] border border-[#454B53] rounded-xl shadow-2xl p-2 z-50 text-xs space-y-1">
              <div className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-[#7F8996] border-b border-[#363B42]">
                Wireshark Filter Presets
              </div>
              <div className="max-h-60 overflow-y-auto space-y-0.5 custom-scrollbar">
                {FILTER_PRESETS.map((preset) => (
                  <button
                    key={preset.query}
                    onClick={() => handleSelectPreset(preset.query)}
                    className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-[#383E45] transition-colors flex flex-col group cursor-pointer"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-[#D1D5DB] group-hover:text-[#F3F4F6]">
                        {preset.label}
                      </span>
                      <code className="text-[10px] font-mono text-[#60A5FA] bg-[#202429] border border-[#454B53] px-1 rounded">
                        {preset.query}
                      </code>
                    </div>
                    <span className="text-[10px] text-[#A1A8B3] mt-0.5">
                      {preset.description}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Validation Error Message or Filter Stats */}
      <div className="flex items-center justify-between text-[11px] px-1">
        {!validation.isValid && validation.error ? (
          <span className="text-[#F87171] flex items-center space-x-1 font-medium">
            <AlertTriangle className="w-3.5 h-3.5 mr-1 inline" />
            {validation.error}
          </span>
        ) : currentFilter ? (
          <span className="text-[#60A5FA] flex items-center space-x-1">
            <span>Filter active:</span>
            <code className="font-mono bg-[#202429] px-1.5 py-0.5 rounded border border-[#454B53] text-[#60A5FA] font-semibold">
              {currentFilter}
            </code>
            <span className="text-[#A1A8B3] ml-1">
              (Showing {matchingCount.toLocaleString()} of {totalCount.toLocaleString()} packets)
            </span>
          </span>
        ) : (
          <span className="text-[#7F8996]">
            Showing all {totalCount.toLocaleString()} captured packets
          </span>
        )}
      </div>
    </div>
  );
};
