import Header from "@/components/Header";
import Footer from "@/components/Footer";
import ReportsInteractive from "./components/ReportsInteractive";

export const metadata = {
  title: "Reports — AASE",
  description: "Interactive vulnerability findings report with severity rankings, evidence, and remediation guidance.",
};

export default function ReportsPage() {
  return (
    <div className="min-h-screen bg-[#080C0A] scanlines">
      <Header />
      <ReportsInteractive />
      <Footer />
    </div>
  );
}