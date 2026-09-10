import Dashboard from '../components/Dashboard';
import { useAppData } from '../context/AppDataContext.jsx';

const OverviewPage = () => {
  const { assets, rating } = useAppData();
  return <Dashboard assets={assets} rating={rating} />;
};

export default OverviewPage;
