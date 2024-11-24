import React, { useState } from "react";
import axios from "axios";
import { BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";

const HostRevealDashboard = () => {
  const [domain, setDomain] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await axios.post("http://localhost:8000/api/investigate/", { domain });
      setData(response.data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1>HostReveal Dashboard</h1>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Enter domain"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        />
        <button type="submit" disabled={loading}>{loading ? "Analyzing..." : "Investigate"}</button>
      </form>

      {data && (
        <div>
          <h2>WHOIS Data</h2>
          <pre>{JSON.stringify(data.whois_data, null, 2)}</pre>
          <h2>DNS Records</h2>
          <pre>{JSON.stringify(data.dns_data, null, 2)}</pre>
          <h2>Traceroute</h2>
          <pre>{JSON.stringify(data.traceroute_data, null, 2)}</pre>
          <h2>SSL Certificate</h2>
          <pre>{JSON.stringify(data.ssl_cert_data, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

export default HostRevealDashboard;
