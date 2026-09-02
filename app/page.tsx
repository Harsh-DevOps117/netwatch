import LandingPage from "./pages/LandingPage";
import ProblemStatement from "./pages/ProblemStatement";
import Solution from "./pages/Solution";

export default function Home() {
  return <div className="px-8">
  <LandingPage />
  <ProblemStatement />
  <Solution />
  </div>;
}
