import jsPDF from "jspdf"
import autoTable from "jspdf-autotable"
import { computeSecurityScore } from "@/lib/score"
import type { FindingsResponse } from "@/lib/api"

export function generateReportPdf(data: FindingsResponse, explanations: Record<number, string>) {
  const doc = new jsPDF()
  const findings = data.findings
  const score = computeSecurityScore(findings)
  const pageWidth = doc.internal.pageSize.getWidth()
  const pageHeight = doc.internal.pageSize.getHeight()
  const margin = 14

  doc.setFontSize(18)
  doc.setFont("helvetica", "bold")
  doc.text("CloudSentinel", margin, 20)

  doc.setFontSize(11)
  doc.setFont("helvetica", "normal")
  doc.text("Security Report", margin, 28)

  doc.setFontSize(9)
  doc.setTextColor(120)
  const scannedAt = data.scanned_at ? new Date(data.scanned_at).toLocaleString() : "unknown"
  doc.text(`Generated: ${new Date().toLocaleString()}   ·   Last scan: ${scannedAt}`, margin, 34)

  doc.setTextColor(0)
  doc.setFontSize(12)
  doc.setFont("helvetica", "bold")
  doc.text(`Security Score: ${score.score}% (${score.label})`, margin, 44)
  doc.setFont("helvetica", "normal")
  doc.text(`Total Findings: ${findings.length}`, margin, 51)

  autoTable(doc, {
    startY: 58,
    head: [["Severity", "Check", "Resource", "Region", "Description"]],
    body: findings.map((f) => [
      f.severity,
      f.check_type,
      `${f.resource_type}\n${f.resource_id}`,
      f.region ?? "-",
      f.description,
    ]),
    styles: { fontSize: 8, cellPadding: 2 },
    headStyles: { fillColor: [30, 30, 35] },
    columnStyles: { 4: { cellWidth: 60 } },
  })

  const findingsWithExplanations = findings.filter((f) => explanations[f.id])
  if (findingsWithExplanations.length > 0) {
    doc.addPage()
    let y = 20

    doc.setFontSize(14)
    doc.setFont("helvetica", "bold")
    doc.text("AI-Generated Explanations & Remediation", margin, y)
    y += 10

    findingsWithExplanations.forEach((f) => {
      const heading = `${f.severity} - ${f.check_type} (${f.resource_id})`
      const headingLines = doc.splitTextToSize(heading, pageWidth - margin * 2) as string[]
      const bodyText = explanations[f.id].replace(/[#*]/g, "")
      const bodyLines = doc.splitTextToSize(bodyText, pageWidth - margin * 2) as string[]

      const neededHeight = headingLines.length * 5 + bodyLines.length * 5 + 10
      if (y + neededHeight > pageHeight - margin) {
        doc.addPage()
        y = 20
      }

      doc.setFontSize(10)
      doc.setFont("helvetica", "bold")
      doc.text(headingLines, margin, y)
      y += headingLines.length * 5 + 2

      doc.setFontSize(9)
      doc.setFont("helvetica", "normal")
      doc.text(bodyLines, margin, y)
      y += bodyLines.length * 5 + 8
    })
  }

  doc.save(`cloudsentinel-report-${new Date().toISOString().slice(0, 10)}.pdf`)
}
