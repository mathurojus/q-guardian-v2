import DependencyGraph from '../components/DependencyGraph';
import { useAppData } from '../context/AppDataContext.jsx';

const TopologyPage = () => {
  const { assets } = useAppData();
  return <DependencyGraph assets={assets} />;
};

export default TopologyPage;
