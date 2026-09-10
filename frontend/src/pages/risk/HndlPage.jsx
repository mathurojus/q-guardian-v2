import HNDLSimulator from '../../components/HNDLSimulator';
import { useAppData } from '../../context/AppDataContext.jsx';

const HndlPage = () => {
  const { assets } = useAppData();
  return <HNDLSimulator assets={assets} />;
};

export default HndlPage;
