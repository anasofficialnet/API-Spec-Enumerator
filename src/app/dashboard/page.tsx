import Header from "@/components/Header";
import Footer from "@/components/Footer";
import DashboardInteractive from "./components/DashboardInteractive";

export const metadata = {
  title: "Dashboard — AASE",
  description: "Upload traffic captures, configure fuzzing campaigns, and view live findings.",
};

export default function DashboardPage() {
  return (
    <div className="min-h-screen">
      <Header />
      <DashboardInteractive />
      <Footer />
    </div>
  );
}
