"use client";
import { useState } from "react";
import "../../styles/globals.css";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    console.log("Email:", email, "Password:", password);
  };

  return (
    <div className="w-full max-w-md bg-gray-800 p-8 rounded-2xl shadow-lg">
      <h2 className="text-2xl font-semibold text-center mb-6">Login</h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300">Email</label>
          <input
            type="email"
            className="w-full mt-1 p-3 rounded-lg bg-gray-700 text-white focus:ring-2 focus:ring-[var(--color-baby-blue)] outline-none"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300">Password</label>
          <input
            type="password"
            className="w-full mt-1 p-3 rounded-lg bg-gray-700 text-white focus:ring-2 focus:ring-[var(--color-baby-blue)] outline-none"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button
          type="submit"
          className="w-full bg-[var(--color-baby-blue)] hover:bg-blue-400 text-gray-900 font-semibold p-3 rounded-lg transition-all"
        >
          Sign In
        </button>
      </form>
      <p className="text-sm text-center text-gray-400 mt-4">
        Don't have an account? <a href="#" className="text-[var(--color-baby-blue)] hover:underline">Sign up</a>
      </p>
    </div>
  );
}
