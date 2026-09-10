import AssetTable from '../components/AssetTable';
import { useAppData } from '../context/AppDataContext.jsx';

const InventoryPage = () => {
  const { assets, handleOpenPlaybook } = useAppData();
  return <AssetTable assets={assets} onPlaybook={handleOpenPlaybook} />;
};

export default InventoryPage;
