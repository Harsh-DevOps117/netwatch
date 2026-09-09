import LandingPage from "./pages/LandingPage";
import ProblemStatement from "./pages/ProblemStatement";
import Solution from "./pages/Solution";
import Goal from "./pages/Goal";
import Footer from "./components/Footer";

export default function Home() {
  return <div className="px-8">
  <LandingPage />
  <ProblemStatement />
  <Solution />
  <Goal />
  <Footer />
  </div>;
}
