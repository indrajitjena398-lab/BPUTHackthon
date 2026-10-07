"use client";

import React, { useState } from "react";
import Link from "next/link";
import { Bell, Sparkles, PlusCircle, Search, ShieldCheck } from "lucide-react";

export default function Topbar({ title, subtitle }: { title?: string; subtitle?: string }) {
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  return (
    <header className="h-16 bg-white border-b border-slate-200 px-8 flex items-center justify-between sticky top-0 z-20">
      {/* Page Title & Subtitle */}
      <div>
        <h1 className="text-lg font-bold text-slate-900 leading-tight">
          {title || "Security Operations Center"}
        </h1>
        {subtitle && (
          <p className="text-xs text-slate-500 font-normal">{subtitle}</p>
        )}
      </div>

      {/* Right Utility Bar */}
      <div className="flex items-center gap-4">
        {/* Environment & Simulation Badge */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-100 border border-slate-200 text-[11px] font-medium text-slate-600">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>Live Protection</span>
          <span className="text-slate-300">|</span>
          <span className="text-blue-600 font-semibold">TEST BENCH</span>
        </div>

        {/* Action Button: New Threat Scan */}
        <Link
          href="/threat-detection"
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold px-3 py-1.5 rounded-lg shadow-xs transition-colors"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          <span>New Analysis</span>
        </Link>

        {/* AI Assistant Quick Link */}
        <Link
          href="/assistant"
          className="flex items-center gap-1.5 border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-medium px-3 py-1.5 rounded-lg transition-colors"
        >
          <Sparkles className="w-3.5 h-3.5 text-blue-600" />
          <span>AI Analyst</span>
        </Link>

        {/* Notifications Icon */}
        <div className="relative">
          <button
            onClick={() => setNotificationsOpen(!notificationsOpen)}
            className="w-8 h-8 rounded-lg border border-slate-200 flex items-center justify-center text-slate-600 hover:bg-slate-50 relative"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-rose-500 rounded-full" />
          </button>

          {notificationsOpen && (
            <div className="absolute right-0 mt-2 w-80 bg-white border border-slate-200 rounded-xl shadow-lg p-3 z-50">
              <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                <span className="text-xs font-bold text-slate-900">Security Alerts</span>
                <span className="text-[10px] text-blue-600 font-medium">3 unread</span>
              </div>
              <div className="py-2 space-y-2 text-xs">
                <div className="p-2 bg-rose-50 border border-rose-100 rounded-lg">
                  <div className="font-semibold text-rose-800">High Risk Phishing Ingested</div>
                  <div className="text-[11px] text-rose-600">service-security-chase.com quarantined</div>
                </div>
                <div className="p-2 bg-amber-50 border border-amber-100 rounded-lg">
                  <div className="font-semibold text-amber-800">Unusual Geolocation Access</div>
                  <div className="text-[11px] text-amber-600">cfo@enterprise.com flagged for step-up MFA</div>
                </div>
                <div className="p-2 bg-slate-50 border border-slate-100 rounded-lg">
                  <div className="font-semibold text-slate-800">IOC Threat Feed Synced</div>
                  <div className="text-[11px] text-slate-500">7 new indicators added to boundary proxy</div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
