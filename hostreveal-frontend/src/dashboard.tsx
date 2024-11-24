"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { AlertCircle, CheckCircle, XCircle } from "lucide-react"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

export default function HostRevealDashboard() {
  const [domain, setDomain] = useState("")
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState(null)
  const [pingProgress, setPingProgress] = useState(0)
  const [ongoingPing, setOngoingPing] = useState([])

  useEffect(() => {
    let interval
    if (loading) {
      interval = setInterval(() => {
        setPingProgress((prevProgress) => {
          if (prevProgress >= 100) {
            clearInterval(interval)
            return 100
          }
          return prevProgress + 10
        })
      }, 500)
    }
    return () => clearInterval(interval)
  }, [loading])

  const simulatePing = () => {
    let count = 0
    const interval = setInterval(() => {
      if (count < 5) {
        setOngoingPing((prev) => [
          ...prev,
          {
            sequence: count + 1,
            time: Math.random() * 100 + 50,
            ttl: 64,
          },
        ])
        count++
      } else {
        clearInterval(interval)
      }
    }, 1000)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setData(null)
    setPingProgress(0)
    setOngoingPing([])

    simulatePing()

    await new Promise((resolve) => setTimeout(resolve, 5000))

    setData({
      whois: {
        registrar: "Example Registrar, Inc.",
        creationDate: "2020-01-01",
        expirationDate: "2025-01-01",
        registrant: {
          name: "John Doe",
          organization: "Example Org",
          email: "john@example.com",
          country: "US",
        },
        nameServers: ["ns1.example.com", "ns2.example.com"],
      },
      dns: [
        { type: "A", value: "192.0.2.1" },
        { type: "AAAA", value: "2001:db8::1" },
        { type: "NS", value: "ns1.example.com" },
        { type: "NS", value: "ns2.example.com" },
        { type: "MX", value: "mail.example.com", priority: 10 },
        { type: "TXT", value: "v=spf1 include:_spf.example.com ~all" },
      ],
      ip: {
        address: "192.0.2.1",
        location: "New York, USA",
        hostname: "host.example.com",
        organization: "Example Org",
        asn: "AS12345",
        isp: "Example ISP",
      },
      traceroute: [
        { hop: 1, ip: "192.168.1.1", rtt: "1.23 ms", hostname: "router.local" },
        { hop: 2, ip: "203.0.113.1", rtt: "5.67 ms", hostname: "isp-gateway.net" },
        { hop: 3, ip: "198.51.100.1", rtt: "10.89 ms", hostname: "core1.example.net" },
        { hop: 4, ip: "192.0.2.1", rtt: "15.42 ms", hostname: "host.example.com" },
      ],
      ping: {
        sent: 5,
        received: 5,
        lost: 0,
        min: "15.3 ms",
        avg: "20.5 ms",
        max: "25.7 ms",
        stddev: "3.2 ms",
      },
      portScan: [
        { port: 80, status: "open", service: "HTTP" },
        { port: 443, status: "open", service: "HTTPS" },
        { port: 22, status: "closed", service: "SSH" },
        { port: 21, status: "filtered", service: "FTP" },
      ],
      sslCert: {
        issuer: "Let's Encrypt Authority X3",
        validFrom: "2023-01-01",
        validTo: "2024-01-01",
        subject: "example.com",
        version: 3,
        serialNumber: "03:a1:57:dc:32:37:a3:98:6a:94:63:c2:d4:e6:07:5e",
      },
      aiAssessment: {
        overall: "Suspicious",
        reasons: [
          "Domain age is less than 1 year",
          "Mismatched organization info in WHOIS and SSL cert",
          "Unusual port configuration",
        ],
        riskScore: 65,
      },
    })
    setLoading(false)
  }

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
      <header className="bg-white dark:bg-gray-800 shadow">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">HostReveal Dashboard</h1>
        </div>
      </header>
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <form onSubmit={handleSubmit} className="mb-8">
          <div className="flex gap-4">
            <Input
              type="text"
              placeholder="Enter domain name"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="flex-grow"
            />
            <Button type="submit" disabled={loading}>
              {loading ? "Analyzing..." : "Investigate"}
            </Button>
          </div>
        </form>

        {loading && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Analysis Progress</CardTitle>
            </CardHeader>
            <CardContent>
              <Progress value={pingProgress} className="w-full" />
            </CardContent>
          </Card>
        )}

        {(loading || data) && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Ongoing Ping Results</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Sequence</TableHead>
                    <TableHead>Time (ms)</TableHead>
                    <TableHead>TTL</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ongoingPing.map((ping, index) => (
                    <TableRow key={index}>
                      <TableCell>{ping.sequence}</TableCell>
                      <TableCell>{ping.time.toFixed(2)}</TableCell>
                      <TableCell>{ping.ttl}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}

        {data && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>WHOIS Data</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableBody>
                    <TableRow>
                      <TableCell className="font-medium">Registrar</TableCell>
                      <TableCell>{data.whois.registrar}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Creation Date</TableCell>
                      <TableCell>{data.whois.creationDate}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Expiration Date</TableCell>
                      <TableCell>{data.whois.expirationDate}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Registrant</TableCell>
                      <TableCell>
                        {data.whois.registrant.name} ({data.whois.registrant.organization})
                        <br />
                        {data.whois.registrant.email}
                        <br />
                        {data.whois.registrant.country}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Name Servers</TableCell>
                      <TableCell>{data.whois.nameServers.join(", ")}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>DNS Records</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Type</TableHead>
                      <TableHead>Value</TableHead>
                      <TableHead>Priority</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.dns.map((record, index) => (
                      <TableRow key={index}>
                        <TableCell>{record.type}</TableCell>
                        <TableCell>{record.value}</TableCell>
                        <TableCell>{record.priority || "-"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>IP Information</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableBody>
                    <TableRow>
                      <TableCell className="font-medium">Address</TableCell>
                      <TableCell>{data.ip.address}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Location</TableCell>
                      <TableCell>{data.ip.location}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Hostname</TableCell>
                      <TableCell>{data.ip.hostname}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Organization</TableCell>
                      <TableCell>{data.ip.organization}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">ASN</TableCell>
                      <TableCell>{data.ip.asn}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">ISP</TableCell>
                      <TableCell>{data.ip.isp}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Traceroute</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Hop</TableHead>
                      <TableHead>IP</TableHead>
                      <TableHead>RTT</TableHead>
                      <TableHead>Hostname</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.traceroute.map((hop, index) => (
                      <TableRow key={index}>
                        <TableCell>{hop.hop}</TableCell>
                        <TableCell>{hop.ip}</TableCell>
                        <TableCell>{hop.rtt}</TableCell>
                        <TableCell>{hop.hostname}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Ping Results</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableBody>
                    <TableRow>
                      <TableCell className="font-medium">Packets</TableCell>
                      <TableCell>
                        Sent: {data.ping.sent}, Received: {data.ping.received}, Lost: {data.ping.lost}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Round-trip Time</TableCell>
                      <TableCell>
                        Min: {data.ping.min}, Avg: {data.ping.avg}, Max: {data.ping.max}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Standard Deviation</TableCell>
                      <TableCell>{data.ping.stddev}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Port Scan</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Port</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Service</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.portScan.map((port, index) => (
                      <TableRow key={index}>
                        <TableCell>{port.port}</TableCell>
                        <TableCell>{port.status}</TableCell>
                        <TableCell>{port.service}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>SSL Certificate</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableBody>
                    <TableRow>
                      <TableCell className="font-medium">Issuer</TableCell>
                      <TableCell>{data.sslCert.issuer}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Valid From</TableCell>
                      <TableCell>{data.sslCert.validFrom}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Valid To</TableCell>
                      <TableCell>{data.sslCert.validTo}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Subject</TableCell>
                      <TableCell>{data.sslCert.subject}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Version</TableCell>
                      <TableCell>{data.sslCert.version}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium">Serial Number</TableCell>
                      <TableCell>{data.sslCert.serialNumber}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>AI Pattern Recognition</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2 mb-4">
                  {data.aiAssessment.overall === "Safe" && (
                    <>
                      <CheckCircle className="text-green-500" />
                      <span className="text-green-500 font-semibold">Safe</span>
                    </>
                  )}
                  {data.aiAssessment.overall === "Suspicious" && (
                    <>
                      <AlertCircle className="text-yellow-500" />
                      <span className="text-yellow-500 font-semibold">Suspicious</span>
                    </>
                  )}
                  {data.aiAssessment.overall === "Malicious" && (
                    <>
                      <XCircle className="text-red-500" />
                      <span className="text-red-500 font-semibold">Malicious</span>
                    </>
                  )}
                </div>
                <p className="mb-2">Risk Score: {data.aiAssessment.riskScore}/100</p>
                <h4 className="font-semibold mb-2">Reasons:</h4>
                <ul className="list-disc pl-5">
                  {data.aiAssessment.reasons.map((reason, index) => (
                    <li key={index}>{reason}</li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            <Card className="md:col-span-2">
              <CardHeader>
                <CardTitle>Analysis Overview</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="summary" className="w-full">
                  <TabsList>
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="timeline">Timeline</TabsTrigger>
                  </TabsList>
                  <TabsContent value="summary">
                    <div className="mt-4">
                      <h3 className="text-lg font-semibold mb-2">Key Findings:</h3>
                      <ul className="list-disc pl-5">
                        <li>Domain registered on {data.whois.creationDate}</li>
                        <li>{data.dns.length} DNS records found</li>
                        <li>
                          {data.portScan.filter((p) => p.status === "open").length} open ports detected
                        </li>
                        <li>SSL certificate valid until {data.sslCert.validTo}</li>
                        <li>AI Risk Score: {data.aiAssessment.riskScore}/100</li>
                      </ul>
                    </div>
                  </TabsContent>
                  <TabsContent value="timeline">
                    <div className="mt-4">
                      <ResponsiveContainer width="100%" height={300}>
                        <BarChart
                          data={[
                            { name: "WHOIS", time: 0.5 },
                            { name: "DNS", time: 0.8 },
                            { name: "IP Info", time: 0.3 },
                            { name: "Traceroute", time: 2.1 },
                            { name: "Port Scan", time: 1.5 },
                            { name: "SSL Cert", time: 0.7 },
                            { name: "AI Analysis", time: 1.2 },
                          ]}
                          margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" />
                          <YAxis label={{ value: "Time (seconds)", angle: -90, position: "insideLeft" }} />
                          <Tooltip />
                          <Bar dataKey="time" fill="#8884d8" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        )}
      </main>
    </div>
  )
}