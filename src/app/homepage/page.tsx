import Header from "@/components/Header";
import Footer from "@/components/Footer";
import HeroSection from "./components/HeroSection";
import HowItWorks from "./components/HowItWorks";
import FeaturesBento from "./components/FeaturesBento";
import StatsSection from "./components/StatsSection";
import CtaSection from "./components/CtaSection";

export const metadata = {
  title: "AASE — Adaptive API Spec Enumerator",
  description:
    "Upload HTTP traffic captures, infer API schemas automatically, and discover vulnerabilities with intelligent fuzzing.",
};

export default function HomepagePage() {
  return (
    <main className="min-h-screen bg-[#080C0A] scanlines">
      <Header />
      <HeroSection />
      <HowItWorks />
      <FeaturesBento />
      <StatsSection />
      <CtaSection />
      <Footer />
    </main>
  );
}