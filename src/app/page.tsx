import dynamic from 'next/dynamic';
import Footer from '@/components/Footer';
import Header from '@/components/Header';

const HeroSection = dynamic(() => import('./homepage/components/HeroSection'));
const HowItWorks = dynamic(() => import('./homepage/components/HowItWorks'));
const StatsSection = dynamic(() => import('./homepage/components/StatsSection'));
const CtaSection = dynamic(() => import('./homepage/components/CtaSection'));

export const metadata = {
  title: 'AASE - Adaptive API Spec Enumerator',
  description:
    'Upload HTTP traffic captures, infer API schemas automatically, and discover vulnerabilities with intelligent fuzzing.',
};

export default function Page() {
  return (
    <main className="min-h-screen">
      <Header />
      <HeroSection />
      <HowItWorks />
      <StatsSection />
      <CtaSection />
      <Footer />
    </main>
  );
}
